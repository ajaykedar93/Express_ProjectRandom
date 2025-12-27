const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const pool = require("../db");

const router = express.Router();

/** ✅ Only these 2 emails can ever be admin */
const ALLOWED_ADMINS = new Set([
  "ajaykedar3790@gmail.com",
  "ajaykedar9657@gmail.com",
]);

/** ✅ JWT secret */
const JWT_SECRET = process.env.JWT_SECRET || "change_this_secret";

/** Helper: normalize email/username */
function normEmail(v) {
  return String(v || "").trim().toLowerCase();
}

/** Helper: hide password */
function sanitizeAdmin(row) {
  if (!row) return row;
  const { password_hash, ...safe } = row;
  return safe;
}

/** Helper: if stored value looks like bcrypt hash */
function isBcryptHash(v) {
  return typeof v === "string" && v.startsWith("$2");
}

/**
 * ✅ Admin Middleware (Single - no duplicate)
 * - Checks Bearer token
 * - Verifies JWT
 * - Checks role=admin
 * - Checks allowed admin emails
 */
function requireAdmin(req, res, next) {
  try {
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;

    if (!token) return res.status(401).json({ message: "Missing admin token" });

    const decoded = jwt.verify(token, JWT_SECRET);

    const role = String(decoded?.role || "").toLowerCase();
    const email = normEmail(decoded?.email);

    if (role !== "admin") return res.status(403).json({ message: "Admin only" });
    if (!email) return res.status(401).json({ message: "Invalid token" });
    if (!ALLOWED_ADMINS.has(email)) return res.status(403).json({ message: "Not allowed" });

    req.admin = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ message: "Unauthorized" });
  }
}

/**
 * ✅ POST /admin/login
 * Accepts: { username, password } OR { email, password }
 */
router.post("/login", async (req, res) => {
  try {
    const email = normEmail(req.body.username || req.body.email);
    const password = String(req.body.password || "");

    if (!email || !password) {
      return res.status(400).json({ message: "username/email and password required" });
    }

    if (!ALLOWED_ADMINS.has(email)) {
      return res.status(403).json({ message: "This email is not allowed as admin" });
    }

    const q = `
      SELECT admin_id, first_name, last_name, email_username, password_hash, mobile_number, dob,
             admin_home_desc, admin_home_image, is_active, token_version, created_at, updated_at
      FROM admin_random
      WHERE LOWER(email_username) = LOWER($1)
      LIMIT 1
    `;
    const result = await pool.query(q, [email]);

    if (result.rowCount === 0) {
      return res.status(401).json({ message: "Admin not found in database" });
    }

    const admin = result.rows[0];

    if (admin.is_active === false) {
      return res.status(403).json({ message: "Admin account is disabled" });
    }

    const stored = admin.password_hash;
    let ok = false;

    if (isBcryptHash(stored)) ok = await bcrypt.compare(password, stored);
    else ok = password === String(stored || "");

    if (!ok) return res.status(401).json({ message: "Invalid password" });

    // ✅ Include token_version in JWT (needed if you want force logout truly work)
    const token = jwt.sign(
      {
        admin_id: admin.admin_id,
        email: normEmail(admin.email_username),
        role: "admin",
        token_version: admin.token_version || 0,
      },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    return res.json({
      message: "Login success",
      token,
      admin: sanitizeAdmin(admin),
    });
  } catch (err) {
    console.error("admin/login error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

/**
 * ✅ GET /admin
 * Get all admins (no password)
 */
router.get("/", requireAdmin, async (req, res) => {
  try {
    const q = `
      SELECT admin_id, first_name, last_name, email_username, mobile_number, dob,
             admin_home_desc, admin_home_image, is_active, token_version, created_at, updated_at
      FROM admin_random
      ORDER BY admin_id DESC
    `;
    const result = await pool.query(q);
    return res.json(result.rows);
  } catch (err) {
    console.error("admin/get all error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

/**
 * ✅ PATCH /admin/:id/force-logout
 * Increments admin token_version
 */
router.patch("/:id/force-logout", requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ message: "Invalid id" });

    await pool.query(
      "UPDATE admin_random SET token_version = token_version + 1 WHERE admin_id = $1",
      [id]
    );

    return res.json({ message: "Admin session invalidated (force logout done)" });
  } catch (e) {
    console.error("force-logout error:", e);
    return res.status(500).json({ message: "Server error" });
  }
});

/**
 * ✅ GET /admin/:id
 * Get single admin details
 */
router.get("/:id", requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ message: "Invalid id" });

    const q = `
      SELECT admin_id, first_name, last_name, email_username, mobile_number, dob,
             admin_home_desc, admin_home_image, is_active, token_version, created_at, updated_at
      FROM admin_random
      WHERE admin_id = $1
      LIMIT 1
    `;
    const result = await pool.query(q, [id]);
    if (result.rowCount === 0) return res.status(404).json({ message: "Admin not found" });

    return res.json(result.rows[0]);
  } catch (err) {
    console.error("admin/get one error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

/**
 * ✅ PATCH /admin/:id/home
 * ONLY update admin_home_desc & admin_home_image
 */
router.patch("/:id/home", requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ message: "Invalid id" });

    const admin_home_desc = req.body.admin_home_desc ?? null;
    const admin_home_image = req.body.admin_home_image ?? null;

    const q = `
      UPDATE admin_random
      SET admin_home_desc = $1,
          admin_home_image = $2
      WHERE admin_id = $3
      RETURNING admin_id, first_name, last_name, email_username, mobile_number, dob,
                admin_home_desc, admin_home_image, is_active, token_version, created_at, updated_at
    `;
    const result = await pool.query(q, [admin_home_desc, admin_home_image, id]);

    if (result.rowCount === 0) return res.status(404).json({ message: "Admin not found" });

    return res.json({ message: "Admin home updated", admin: result.rows[0] });
  } catch (err) {
    console.error("admin/update home error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

/**
 * ✅ PUT /admin/:id
 * Update admin fields (NO register)
 */
router.put("/:id", requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ message: "Invalid id" });

    const first_name = req.body.first_name ?? null;
    const last_name = req.body.last_name ?? null;

    const email_username_raw = req.body.email_username ?? null;
    const email_username = email_username_raw ? normEmail(email_username_raw) : null;

    if (email_username && !ALLOWED_ADMINS.has(email_username)) {
      return res.status(403).json({ message: "Admin email must be one of the allowed 2 emails" });
    }

    const mobile_number = req.body.mobile_number ?? null;

    let dob = req.body.dob ?? null;
    if (typeof dob === "string" && dob.trim()) {
      const parsed = new Date(dob.trim());
      if (!Number.isNaN(parsed.getTime())) {
        const yyyy = parsed.getFullYear();
        const mm = String(parsed.getMonth() + 1).padStart(2, "0");
        const dd = String(parsed.getDate()).padStart(2, "0");
        dob = `${yyyy}-${mm}-${dd}`;
      }
    }

    const is_active = typeof req.body.is_active === "boolean" ? req.body.is_active : null;

    const password = req.body.password ? String(req.body.password) : null;
    let password_hash = null;
    if (password) password_hash = await bcrypt.hash(password, 10);

    const fields = [];
    const values = [];
    let i = 1;

    const add = (col, val) => {
      fields.push(`${col} = $${i++}`);
      values.push(val);
    };

    if (first_name !== null) add("first_name", first_name);
    if (last_name !== null) add("last_name", last_name);
    if (email_username !== null) add("email_username", email_username);
    if (mobile_number !== null) add("mobile_number", mobile_number);
    if (dob !== null) add("dob", dob);
    if (is_active !== null) add("is_active", is_active);
    if (password_hash !== null) add("password_hash", password_hash);

    if (!fields.length) return res.status(400).json({ message: "No fields provided to update" });

    values.push(id);

    const q = `
      UPDATE admin_random
      SET ${fields.join(", ")}
      WHERE admin_id = $${i}
      RETURNING admin_id, first_name, last_name, email_username, mobile_number, dob,
                admin_home_desc, admin_home_image, is_active, token_version, created_at, updated_at
    `;
    const result = await pool.query(q, values);

    if (result.rowCount === 0) return res.status(404).json({ message: "Admin not found" });

    return res.json({ message: "Admin updated", admin: result.rows[0] });
  } catch (err) {
    console.error("admin/update error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

/**
 * ✅ DELETE /admin/:id
 */
router.delete("/:id", requireAdmin, async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ message: "Invalid id" });

    const q = `DELETE FROM admin_random WHERE admin_id = $1 RETURNING admin_id`;
    const result = await pool.query(q, [id]);

    if (result.rowCount === 0) return res.status(404).json({ message: "Admin not found" });

    return res.json({ message: "Admin deleted", admin_id: result.rows[0].admin_id });
  } catch (err) {
    console.error("admin/delete error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

/**
 * ✅ PATCH /admin/users/:id/force-logout
 * Force logout normal user
 */
router.patch("/users/:id/force-logout", requireAdmin, async (req, res) => {
  try {
    const { id } = req.params; // UUID

    const result = await pool.query(
      `UPDATE register_random
       SET token_version = token_version + 1
       WHERE id = $1
       RETURNING id, full_name, email_address, token_version`,
      [id]
    );

    if (result.rowCount === 0) return res.status(404).json({ message: "User not found" });

    return res.json({ message: "User force logout done", user: result.rows[0] });
  } catch (err) {
    console.error("ADMIN FORCE LOGOUT USER ERROR:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

module.exports = router;
