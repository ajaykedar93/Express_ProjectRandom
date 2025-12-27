// auth.js (USER ONLY)
const express = require("express");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const pool = require("../db");

const { sendOTP, sendEmail } = require("../utils/mailer");

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET || "change_this_secret";
const USER_TOKEN_EXP = process.env.USER_TOKEN_EXP || "7d";

/* OTP store */
const OTP_TTL_MS = 10 * 60 * 1000;
const MAX_OTP_ATTEMPTS = 5;
const OTP_RESEND_COOLDOWN_MS = 30 * 1000;

const otpStoreByEmail = new Map();
const verifiedEmailTokenStore = new Map();

/* helpers */
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

/* ✅ user jwt verify + token_version check */
async function requireUserJWT(req, res, next) {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
    if (!token) return res.status(401).json({ message: "Missing token" });

    const decoded = jwt.verify(token, JWT_SECRET);
    if (!decoded?.id) return res.status(401).json({ message: "Invalid token" });

    const db = await pool.query(
      "SELECT token_version FROM register_random WHERE id=$1 LIMIT 1",
      [decoded.id]
    );
    if (db.rowCount === 0) return res.status(401).json({ message: "User not found" });

    const dbVer = Number(db.rows[0].token_version || 0);
    const tokVer = Number(decoded.token_version || 0);

    if (dbVer !== tokVer) {
      return res.status(401).json({ message: "Session expired. Please login again." });
    }

    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ message: "Unauthorized" });
  }
}

/* SEND OTP */
router.post("/send-otp", async (req, res) => {
  try {
    const email_address = normalizeEmail(req.body.email_address);
    if (!email_address || !isValidEmail(email_address)) {
      return res.status(400).json({ message: "Valid email required" });
    }

    const existing = await pool.query(
      `SELECT id FROM register_random WHERE email_address=$1 LIMIT 1`,
      [email_address]
    );
    if (existing.rows.length > 0) {
      return res.status(409).json({ message: "Email already registered" });
    }

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

    await sendOTP(email_address, otp, 10);
    return res.json({ message: "OTP sent successfully" });
  } catch (err) {
    console.error("SEND OTP ERROR:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

/* VERIFY OTP */
router.post("/verify-otp", async (req, res) => {
  try {
    const email_address = normalizeEmail(req.body.email_address);
    const otp = String(req.body.otp || "").trim();

    if (!email_address || !isValidEmail(email_address))
      return res.status(400).json({ message: "Valid email required" });
    if (!/^[0-9]{6}$/.test(otp))
      return res.status(400).json({ message: "Valid 6-digit OTP required" });

    const rec = otpStoreByEmail.get(email_address);
    if (!rec) return res.status(400).json({ message: "OTP not found" });
    if (Date.now() > rec.expiresAt) {
      otpStoreByEmail.delete(email_address);
      return res.status(400).json({ message: "OTP expired" });
    }
    if (rec.attempts >= MAX_OTP_ATTEMPTS) {
      otpStoreByEmail.delete(email_address);
      return res.status(429).json({ message: "Too many attempts" });
    }

    rec.attempts += 1;
    const ok = await bcrypt.compare(otp, rec.otpHash);
    if (!ok) return res.status(400).json({ message: "Invalid OTP" });

    otpStoreByEmail.delete(email_address);
    const verify_token = makeVerifyToken();
    verifiedEmailTokenStore.set(verify_token, {
      email: email_address,
      expiresAt: Date.now() + 15 * 60 * 1000,
    });

    return res.json({ message: "Email verified", verify_token });
  } catch (err) {
    console.error("VERIFY OTP ERROR:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

/* REGISTER */
router.post("/register", async (req, res) => {
  try {
    const {
      first_name, last_name, mobile_number, email_address, password,
      village_city, pincode, state, district, taluka, verify_token,
    } = req.body;

    const email = normalizeEmail(email_address);

    if (!first_name || !last_name || !mobile_number || !email || !password)
      return res.status(400).json({ message: "Required fields missing" });
    if (!isValidMobile10(mobile_number))
      return res.status(400).json({ message: "Mobile number must be 10 digits" });
    if (!isValidEmail(email))
      return res.status(400).json({ message: "Invalid email address" });
    if (!isValidPincode6OrEmpty(pincode))
      return res.status(400).json({ message: "Pincode must be 6 digits" });

    if (!verify_token)
      return res.status(400).json({ message: "Email verification required" });

    const tokenRec = verifiedEmailTokenStore.get(verify_token);
    if (!tokenRec || Date.now() > tokenRec.expiresAt || tokenRec.email !== email)
      return res.status(401).json({ message: "Invalid verify_token" });

    const dup = await pool.query(
      `SELECT id FROM register_random
       WHERE email_address=$1 OR mobile_number=$2 LIMIT 1`,
      [email, String(mobile_number).trim()]
    );
    if (dup.rows.length > 0)
      return res.status(409).json({ message: "Email or Mobile already registered" });

    const password_hash = await bcrypt.hash(String(password), 10);

    const result = await pool.query(
      `INSERT INTO register_random
       (first_name,last_name,mobile_number,email_address,village_city,pincode,state,district,taluka,password_hash)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
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

    verifiedEmailTokenStore.delete(verify_token);
    return res.status(201).json({ message: "Registered successfully", user: result.rows[0] });
  } catch (err) {
    console.error("REGISTER ERROR:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

/* LOGIN */
router.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ message: "Username & password required" });

    const userNameStr = String(username).trim();
    const isEmail = userNameStr.includes("@");

    const userRes = await pool.query(
      `SELECT * FROM register_random
       WHERE ${isEmail ? "email_address" : "mobile_number"}=$1 LIMIT 1`,
      [isEmail ? normalizeEmail(userNameStr) : userNameStr]
    );
    if (userRes.rows.length === 0)
      return res.status(401).json({ message: "Invalid credentials" });

    const user = userRes.rows[0];
    const ok = await bcrypt.compare(String(password), user.password_hash);
    if (!ok) return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign(
      { id: user.id, role: "user", token_version: Number(user.token_version || 0) },
      JWT_SECRET,
      { expiresIn: USER_TOKEN_EXP }
    );

    return res.json({
      message: "Login success",
      token,
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

/* ✅ USER SELF LOGOUT */
router.post("/logout", requireUserJWT, async (req, res) => {
  try {
    await pool.query(
      `UPDATE register_random
       SET token_version = token_version + 1
       WHERE id = $1`,
      [req.user.id]
    );
    return res.json({ message: "Logged out successfully" });
  } catch (err) {
    console.error("LOGOUT ERROR:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

/* USERS LIST/CRUD (same) */
router.get("/users", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, first_name, last_name, full_name, mobile_number, email_address,
              village_city, pincode, state, district, taluka, created_at
       FROM register_random ORDER BY created_at DESC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error("GET USERS ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});

router.get("/users/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      `SELECT id, first_name, last_name, full_name, mobile_number, email_address,
              village_city, pincode, state, district, taluka, created_at
       FROM register_random WHERE id=$1`,
      [id]
    );
    if (result.rows.length === 0)
      return res.status(404).json({ message: "User not found" });
    res.json(result.rows[0]);
  } catch (err) {
    console.error("GET USER ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});

router.put("/users/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const {
      first_name, last_name, mobile_number, email_address,
      village_city, pincode, state, district, taluka, password,
    } = req.body;

    if (mobile_number && !isValidMobile10(mobile_number))
      return res.status(400).json({ message: "Mobile number must be 10 digits" });
    if (email_address && !isValidEmail(email_address))
      return res.status(400).json({ message: "Invalid email address" });
    if (!isValidPincode6OrEmpty(pincode))
      return res.status(400).json({ message: "Pincode must be 6 digits" });

    const newEmail = email_address ? normalizeEmail(email_address) : null;

    if (newEmail || mobile_number) {
      const dup = await pool.query(
        `SELECT id FROM register_random
         WHERE (email_address=$1 OR mobile_number=$2) AND id<>$3 LIMIT 1`,
        [newEmail || "", mobile_number || "", id]
      );
      if (dup.rows.length > 0)
        return res.status(409).json({ message: "Email or Mobile already exists" });
    }

    let password_hash = null;
    if (password) password_hash = await bcrypt.hash(String(password), 10);

    const result = await pool.query(
      `UPDATE register_random SET
        first_name=COALESCE($1,first_name),
        last_name=COALESCE($2,last_name),
        mobile_number=COALESCE($3,mobile_number),
        email_address=COALESCE($4,email_address),
        village_city=COALESCE($5,village_city),
        pincode=COALESCE($6,pincode),
        state=COALESCE($7,state),
        district=COALESCE($8,district),
        taluka=COALESCE($9,taluka),
        password_hash=COALESCE($10,password_hash)
       WHERE id=$11
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

    if (result.rows.length === 0)
      return res.status(404).json({ message: "User not found" });
    res.json({ message: "Updated successfully", user: result.rows[0] });
  } catch (err) {
    console.error("UPDATE ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});

router.delete("/users/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      `DELETE FROM register_random WHERE id=$1 RETURNING id`,
      [id]
    );
    if (result.rows.length === 0)
      return res.status(404).json({ message: "User not found" });
    res.json({ message: "Deleted successfully" });
  } catch (err) {
    console.error("DELETE ERROR:", err);
    res.status(500).json({ message: "Server error" });
  }
});

module.exports = router;
