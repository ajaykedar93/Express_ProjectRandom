const express = require("express");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const pool = require("../db");

// Mailer (Mailjet HTTPS API)
const { sendOTP } = require("../utils/mailer");

const router = express.Router();

/**
 * OTP STORE (in-memory)
 * NOTE: resets when server restarts.
 * For production: store in DB/Redis.
 */
const OTP_TTL_MS = 10 * 60 * 1000; // 10 minutes
const MAX_OTP_ATTEMPTS = 5;
const OTP_RESEND_COOLDOWN_MS = 30 * 1000; // 30 seconds resend lock

// email -> { otpHash, expiresAt, attempts, lastSentAt }
const otpStoreByEmail = new Map();

// verify_token -> { email, expiresAt }
const verifiedTokenStore = new Map();

/* ---------------- Helpers ---------------- */
const normalizeEmail = (email) => String(email || "").trim().toLowerCase();
const isValidEmail = (email) =>
  /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email || "").trim());

function generateOtp6() {
  return String(crypto.randomInt(100000, 1000000));
}
function makeVerifyToken() {
  return crypto.randomBytes(24).toString("hex");
}

/* -------------------------------------------------------
   1) SEND OTP (Forgot Password)
   POST /api/auth/forgot/send-otp
   body: { email_address }
-------------------------------------------------------- */
router.post("/send-otp", async (req, res) => {
  try {
    const email_address = normalizeEmail(req.body.email_address);

    if (!email_address || !isValidEmail(email_address)) {
      return res.status(400).json({ message: "Valid email required" });
    }

    // ✅ must exist in DB (forgot password)
    const user = await pool.query(
      `SELECT id FROM register_random WHERE email_address=$1 LIMIT 1`,
      [email_address]
    );
    if (user.rows.length === 0) {
      return res.status(404).json({ message: "Email not found" });
    }

    // ✅ resend cooldown
    const prev = otpStoreByEmail.get(email_address);
    if (prev?.lastSentAt && Date.now() - prev.lastSentAt < OTP_RESEND_COOLDOWN_MS) {
      return res.status(429).json({ message: "Please wait before resending OTP" });
    }

    const otp = generateOtp6();
    const otpHash = await bcrypt.hash(otp, 10);

    otpStoreByEmail.set(email_address, {
      otpHash,
      expiresAt: Date.now() + OTP_TTL_MS,
      attempts: 0,
      lastSentAt: Date.now(),
    });

    // ✅ Send OTP email (your mailer.js supports sendOTP(to, otp, expiresInMins))
    await sendOTP(email_address, otp, 10);

    return res.json({ message: "OTP sent successfully" });
  } catch (err) {
    console.error("FORGOT SEND OTP ERROR:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

/* -------------------------------------------------------
   2) VERIFY OTP (Forgot Password)
   POST /api/auth/forgot/verify-otp
   body: { email_address, otp }
   returns: { verify_token }
-------------------------------------------------------- */
router.post("/verify-otp", async (req, res) => {
  try {
    const email_address = normalizeEmail(req.body.email_address);
    const otp = String(req.body.otp || "").trim();

    if (!email_address || !isValidEmail(email_address)) {
      return res.status(400).json({ message: "Valid email required" });
    }
    if (!/^[0-9]{6}$/.test(otp)) {
      return res.status(400).json({ message: "Valid 6-digit OTP required" });
    }

    const rec = otpStoreByEmail.get(email_address);
    if (!rec) return res.status(400).json({ message: "OTP not found. Send OTP again." });

    if (Date.now() > rec.expiresAt) {
      otpStoreByEmail.delete(email_address);
      return res.status(400).json({ message: "OTP expired. Send OTP again." });
    }

    if (rec.attempts >= MAX_OTP_ATTEMPTS) {
      otpStoreByEmail.delete(email_address);
      return res.status(429).json({ message: "Too many attempts. Send OTP again." });
    }

    rec.attempts += 1;
    const ok = await bcrypt.compare(otp, rec.otpHash);
    if (!ok) return res.status(400).json({ message: "Invalid OTP" });

    // OTP verified -> issue verify token
    otpStoreByEmail.delete(email_address);

    const verify_token = makeVerifyToken();
    verifiedTokenStore.set(verify_token, {
      email: email_address,
      expiresAt: Date.now() + 15 * 60 * 1000, // 15 min to reset password
    });

    return res.json({ message: "OTP verified", verify_token });
  } catch (err) {
    console.error("FORGOT VERIFY OTP ERROR:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

/* -------------------------------------------------------
   3) RESET PASSWORD (Forgot Password)
   POST /api/auth/forgot/reset-password
   body: { email_address, new_password, verify_token }
-------------------------------------------------------- */
router.post("/reset-password", async (req, res) => {
  try {
    const email_address = normalizeEmail(req.body.email_address);
    const new_password = String(req.body.new_password || "");
    const verify_token = String(req.body.verify_token || "");

    if (!email_address || !isValidEmail(email_address)) {
      return res.status(400).json({ message: "Valid email required" });
    }
    if (!new_password || new_password.length < 6) {
      return res.status(400).json({ message: "Password must be at least 6 characters" });
    }
    if (!verify_token) {
      return res.status(400).json({ message: "verify_token required" });
    }

    const tokenRec = verifiedTokenStore.get(verify_token);
    if (!tokenRec) {
      return res.status(401).json({ message: "Invalid verify_token. Verify OTP again." });
    }
    if (Date.now() > tokenRec.expiresAt) {
      verifiedTokenStore.delete(verify_token);
      return res.status(401).json({ message: "verify_token expired. Verify OTP again." });
    }
    if (tokenRec.email !== email_address) {
      return res.status(401).json({ message: "verify_token does not match email" });
    }

    // ✅ user must exist
    const user = await pool.query(
      `SELECT id FROM register_random WHERE email_address=$1 LIMIT 1`,
      [email_address]
    );
    if (user.rows.length === 0) {
      return res.status(404).json({ message: "Email not found" });
    }

    const password_hash = await bcrypt.hash(new_password, 10);

    await pool.query(
      `UPDATE register_random
       SET password_hash = $1
       WHERE email_address = $2`,
      [password_hash, email_address]
    );

    // one-time token use
    verifiedTokenStore.delete(verify_token);

    return res.json({ message: "Password updated successfully" });
  } catch (err) {
    console.error("FORGOT RESET PASSWORD ERROR:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

module.exports = router;
