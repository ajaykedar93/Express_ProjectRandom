const express = require("express");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const pool = require("../db");

// Mailer (Mailjet HTTPS API): sendOTP / sendEmail
const { sendOTP, sendEmail } = require("../utils/mailer");

const router = express.Router();

/**
 * OTP STORE (in-memory)
 * NOTE: resets when server restarts.
 * For production: store in DB/Redis.
 */
const OTP_TTL_MS = 10 * 60 * 1000; // 10 minutes
const MAX_OTP_ATTEMPTS = 5;

// optional: stop spamming resend otp
const OTP_RESEND_COOLDOWN_MS = 30 * 1000; // 30 sec

const otpStoreByEmail = new Map(); // email -> { otpHash, expiresAt, attempts, lastSentAt }
const verifiedEmailTokenStore = new Map(); // token -> { email, expiresAt }

/* ---------------- Helpers ---------------- */
const normalizeEmail = (email) => String(email || "").trim().toLowerCase();

const isValidEmail = (email) =>
  /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email || "").trim());

const isValidMobile10 = (m) => /^[0-9]{10}$/.test(String(m || "").trim());
const isValidPincode6OrEmpty = (p) => !p || /^[0-9]{6}$/.test(String(p).trim());

function generateOtp6() {
  return String(crypto.randomInt(100000, 1000000));
}

function makeVerifyToken() {
  return crypto.randomBytes(24).toString("hex");
}

/* ---------------- SEND OTP ----------------
POST /api/auth/send-otp
body: { email_address }
*/
router.post("/send-otp", async (req, res) => {
  try {
    const email_address = normalizeEmail(req.body.email_address);

    if (!email_address || !isValidEmail(email_address)) {
      return res.status(400).json({ message: "Valid email required" });
    }

    // Optional: block if already registered
    const existing = await pool.query(
      `SELECT id FROM register_random WHERE email_address=$1 LIMIT 1`,
      [email_address]
    );
    if (existing.rows.length > 0) {
      return res.status(409).json({ message: "Email already registered" });
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

    // ✅ matches your mailer.js: sendOTP(to, otp, expiresInMins)
    await sendOTP(email_address, otp, 10);

    return res.json({ message: "OTP sent successfully" });
  } catch (err) {
    console.error("SEND OTP ERROR:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

/* ---------------- VERIFY OTP ----------------
POST /api/auth/verify-otp
body: { email_address, otp }
returns: { verify_token }
*/
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
    if (!ok) {
      return res.status(400).json({ message: "Invalid OTP" });
    }

    // ✅ OTP verified -> issue verify token
    otpStoreByEmail.delete(email_address);

    const verify_token = makeVerifyToken();
    verifiedEmailTokenStore.set(verify_token, {
      email: email_address,
      expiresAt: Date.now() + 15 * 60 * 1000, // 15 minutes to complete register
    });

    return res.json({ message: "Email verified", verify_token });
  } catch (err) {
    console.error("VERIFY OTP ERROR:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

/* ---------------- Register ----------------
POST /api/auth/register
body:
  first_name,last_name,mobile_number,email_address,password,
  village_city,pincode,state,district,taluka (optional),
  verify_token (REQUIRED)
*/
router.post("/register", async (req, res) => {
  try {
    const {
      first_name,
      last_name,
      mobile_number,
      email_address,
      password,
      village_city,
      pincode,
      state,
      district,
      taluka,
      verify_token,
    } = req.body;

    const email = normalizeEmail(email_address);

    if (!first_name || !last_name || !mobile_number || !email || !password) {
      return res.status(400).json({ message: "Required fields missing" });
    }
    if (!isValidMobile10(mobile_number)) {
      return res.status(400).json({ message: "Mobile number must be 10 digits" });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ message: "Invalid email address" });
    }
    if (!isValidPincode6OrEmpty(pincode)) {
      return res.status(400).json({ message: "Pincode must be 6 digits" });
    }

    // ✅ enforce OTP verification
    if (!verify_token) {
      return res.status(400).json({ message: "Email verification required (missing verify_token)" });
    }
    const tokenRec = verifiedEmailTokenStore.get(verify_token);
    if (!tokenRec) {
      return res.status(401).json({ message: "Invalid verify_token. Verify email again." });
    }
    if (Date.now() > tokenRec.expiresAt) {
      verifiedEmailTokenStore.delete(verify_token);
      return res.status(401).json({ message: "verify_token expired. Verify email again." });
    }
    if (tokenRec.email !== email) {
      return res.status(401).json({ message: "verify_token does not match email" });
    }

    // check duplicate email or mobile
    const dup = await pool.query(
      `SELECT id FROM register_random
       WHERE email_address = $1 OR mobile_number = $2
       LIMIT 1`,
      [email, String(mobile_number).trim()]
    );

    if (dup.rows.length > 0) {
      return res.status(409).json({ message: "Email or Mobile already registered" });
    }

    const password_hash = await bcrypt.hash(String(password), 10);

    const result = await pool.query(
      `INSERT INTO register_random
        (first_name,last_name,mobile_number,email_address,village_city,pincode,state,district,taluka,password_hash)
       VALUES
        ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
       RETURNING id, first_name, last_name, full_name, mobile_number, email_address,
                 village_city, pincode, state, district, taluka, created_at`,
      [
        String(first_name).trim(),
        String(last_name).trim(),
        String(mobile_number).trim(),
        email,
        village_city || null,
        pincode || null,
        state || null,
        district || null,
        taluka || null,
        password_hash,
      ]
    );

    // one-time token use
    verifiedEmailTokenStore.delete(verify_token);

    return res.status(201).json({ message: "Registered successfully", user: result.rows[0] });
  } catch (err) {
    console.error("REGISTER ERROR:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

/* ---------------- Login ----------------
POST /api/auth/login
body: username (email OR mobile), password
*/
router.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ message: "Username & password required" });
    }

    const userNameStr = String(username).trim();
    const isEmail = userNameStr.includes("@");

    const userRes = await pool.query(
      `SELECT * FROM register_random
       WHERE ${isEmail ? "email_address" : "mobile_number"} = $1
       LIMIT 1`,
      [isEmail ? normalizeEmail(userNameStr) : userNameStr]
    );

    if (userRes.rows.length === 0) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const user = userRes.rows[0];
    const ok = await bcrypt.compare(String(password), user.password_hash);
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });

    return res.json({
      message: "Login success",
      user: {
        id: user.id,
        first_name: user.first_name,
        last_name: user.last_name,
        full_name: user.full_name,
        mobile_number: user.mobile_number,
        email_address: user.email_address,
        village_city: user.village_city,
        pincode: user.pincode,
        state: user.state,
        district: user.district,
        taluka: user.taluka,
        created_at: user.created_at,
      },
    });
  } catch (err) {
    console.error("LOGIN ERROR:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

/* ---------------- GET ALL USERS ---------------- */
router.get("/users", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, first_name, last_name, full_name, mobile_number, email_address,
              village_city, pincode, state, district, taluka, created_at
       FROM register_random
       ORDER BY created_at DESC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error("GET USERS ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});

/* ---------------- GET SINGLE USER ---------------- */
router.get("/users/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      `SELECT id, first_name, last_name, full_name, mobile_number, email_address,
              village_city, pincode, state, district, taluka, created_at
       FROM register_random
       WHERE id=$1`,
      [id]
    );

    if (result.rows.length === 0) return res.status(404).json({ message: "User not found" });
    res.json(result.rows[0]);
  } catch (err) {
    console.error("GET USER ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});

/* ---------------- UPDATE USER ---------------- */
router.put("/users/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const {
      first_name,
      last_name,
      mobile_number,
      email_address,
      village_city,
      pincode,
      state,
      district,
      taluka,
      password,
    } = req.body;

    if (mobile_number && !isValidMobile10(mobile_number)) {
      return res.status(400).json({ message: "Mobile number must be 10 digits" });
    }
    if (email_address && !isValidEmail(email_address)) {
      return res.status(400).json({ message: "Invalid email address" });
    }
    if (!isValidPincode6OrEmpty(pincode)) {
      return res.status(400).json({ message: "Pincode must be 6 digits" });
    }

    const newEmail = email_address ? normalizeEmail(email_address) : null;

    // check duplicates if changing
    if (newEmail || mobile_number) {
      const dup = await pool.query(
        `SELECT id FROM register_random
         WHERE (email_address = $1 OR mobile_number = $2) AND id <> $3
         LIMIT 1`,
        [newEmail || "", mobile_number || "", id]
      );
      if (dup.rows.length > 0) {
        return res.status(409).json({ message: "Email or Mobile already exists" });
      }
    }

    let password_hash = null;
    if (password) password_hash = await bcrypt.hash(String(password), 10);

    const result = await pool.query(
      `UPDATE register_random SET
        first_name    = COALESCE($1, first_name),
        last_name     = COALESCE($2, last_name),
        mobile_number = COALESCE($3, mobile_number),
        email_address = COALESCE($4, email_address),
        village_city  = COALESCE($5, village_city),
        pincode       = COALESCE($6, pincode),
        state         = COALESCE($7, state),
        district      = COALESCE($8, district),
        taluka        = COALESCE($9, taluka),
        password_hash = COALESCE($10, password_hash)
       WHERE id = $11
       RETURNING id, first_name, last_name, full_name, mobile_number, email_address,
                 village_city, pincode, state, district, taluka, created_at`,
      [
        first_name?.trim() ?? null,
        last_name?.trim() ?? null,
        mobile_number ?? null,
        newEmail,
        village_city ?? null,
        pincode ?? null,
        state ?? null,
        district ?? null,
        taluka ?? null,
        password_hash,
        id,
      ]
    );

    if (result.rows.length === 0) return res.status(404).json({ message: "User not found" });
    res.json({ message: "Updated successfully", user: result.rows[0] });
  } catch (err) {
    console.error("UPDATE ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});

/* ---------------- DELETE USER ---------------- */
router.delete("/users/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      `DELETE FROM register_random
       WHERE id=$1
       RETURNING id`,
      [id]
    );

    if (result.rows.length === 0) return res.status(404).json({ message: "User not found" });
    res.json({ message: "Deleted successfully" });
  } catch (err) {
    console.error("DELETE ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});

module.exports = router;
