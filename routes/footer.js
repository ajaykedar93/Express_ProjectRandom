// routes/footer.js
const express = require("express");
const router = express.Router();
const pool = require("../db");

// Helper: safely parse JSON if string sent from frontend
function normalizeJsonb(value) {
  if (value === undefined || value === null || value === "") return null;

  // If already object/array -> ok
  if (typeof value === "object") return value;

  // If string -> try parse
  if (typeof value === "string") {
    try {
      return JSON.parse(value);
    } catch (e) {
      return "__INVALID_JSON__";
    }
  }

  return "__INVALID_JSON__";
}

/**
 * ✅ POST /api/footer
 * Add footer
 * Body:
 * {
 *   "footer_tagline": "Built with ❤️ in India",
 *   "footer_description": "Short optional text",
 *   "footer_links": [{"name":"instagram","url":"..."},{"name":"whatsapp","url":"..."}],
 *   "is_active": true
 * }
 */
router.post("/", async (req, res) => {
  try {
    const { footer_tagline, footer_description, footer_links, is_active } =
      req.body;

    if (!footer_tagline || String(footer_tagline).trim() === "") {
      return res.status(400).json({
        success: false,
        message: "footer_tagline is required",
      });
    }

    const linksJson = normalizeJsonb(footer_links);
    if (linksJson === "__INVALID_JSON__") {
      return res.status(400).json({
        success: false,
        message: "footer_links must be valid JSON (array/object)",
      });
    }

    const result = await pool.query(
      `INSERT INTO footer_admin (footer_tagline, footer_description, footer_links, is_active)
       VALUES ($1, $2, $3::jsonb, COALESCE($4, TRUE))
       RETURNING *`,
      [
        footer_tagline.trim(),
        footer_description ? String(footer_description).trim() : null,
        linksJson,
        is_active,
      ]
    );

    return res.status(201).json({
      success: true,
      message: "Footer created successfully",
      data: result.rows[0],
    });
  } catch (err) {
    console.error("POST /footer error:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

/**
 * ✅ GET /api/footer
 * Get all footers (latest first)
 */
router.get("/", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM footer_admin
       ORDER BY created_at DESC`
    );

    return res.json({ success: true, data: result.rows });
  } catch (err) {
    console.error("GET /footer error:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

/**
 * ✅ GET /api/footer/active
 * Get active footer (latest active)
 */
router.get("/active", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM footer_admin
       WHERE is_active = TRUE
       ORDER BY updated_at DESC, created_at DESC
       LIMIT 1`
    );

    return res.json({ success: true, data: result.rows[0] || null });
  } catch (err) {
    console.error("GET /footer/active error:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

/**
 * ✅ GET /api/footer/:id
 * Get footer by id
 */
router.get("/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      `SELECT * FROM footer_admin WHERE footer_id = $1`,
      [id]
    );

    if (result.rowCount === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Footer not found" });
    }

    return res.json({ success: true, data: result.rows[0] });
  } catch (err) {
    console.error("GET /footer/:id error:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

/**
 * ✅ PUT /api/footer/:id
 * Update footer
 * Body can include any fields:
 * { footer_tagline, footer_description, footer_links, is_active }
 */
router.put("/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { footer_tagline, footer_description, footer_links, is_active } =
      req.body;

    const linksJson = normalizeJsonb(footer_links);
    if (linksJson === "__INVALID_JSON__") {
      return res.status(400).json({
        success: false,
        message: "footer_links must be valid JSON (array/object)",
      });
    }

    // Update only provided fields (COALESCE keeps old value if null/undefined)
    const result = await pool.query(
      `UPDATE footer_admin
       SET
         footer_tagline = COALESCE($1, footer_tagline),
         footer_description = COALESCE($2, footer_description),
         footer_links = COALESCE($3::jsonb, footer_links),
         is_active = COALESCE($4, is_active),
         updated_at = CURRENT_TIMESTAMP
       WHERE footer_id = $5
       RETURNING *`,
      [
        footer_tagline !== undefined ? String(footer_tagline).trim() : null,
        footer_description !== undefined
          ? (footer_description === null ? null : String(footer_description).trim())
          : null,
        footer_links !== undefined ? linksJson : null,
        is_active !== undefined ? is_active : null,
        id,
      ]
    );

    if (result.rowCount === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Footer not found" });
    }

    return res.json({
      success: true,
      message: "Footer updated successfully",
      data: result.rows[0],
    });
  } catch (err) {
    console.error("PUT /footer/:id error:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

/**
 * ✅ DELETE /api/footer/:id
 * Delete footer by id
 */
router.delete("/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      `DELETE FROM footer_admin WHERE footer_id = $1 RETURNING *`,
      [id]
    );

    if (result.rowCount === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Footer not found" });
    }

    return res.json({
      success: true,
      message: "Footer deleted successfully",
      data: result.rows[0],
    });
  } catch (err) {
    console.error("DELETE /footer/:id error:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

module.exports = router;
