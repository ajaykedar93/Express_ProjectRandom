const express = require("express");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const pool = require("../db");

const router = express.Router();

/* ======================================================
   UPLOAD SETUP
====================================================== */

const UPLOAD_DIR = path.join(__dirname, "..", "uploads", "textdocs");
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, UPLOAD_DIR),
  filename: (_, file, cb) => {
    const safe = file.originalname.replace(/[^a-zA-Z0-9._-]/g, "_");
    cb(null, `${Date.now()}_${safe}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
});

/* ======================================================
   HELPERS
====================================================== */

const isUUID = (v) =>
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
    v
  );

const safeJSON = (s, fallback = {}) => {
  try {
    return JSON.parse(s);
  } catch {
    return fallback;
  }
};

const deleteFile = async (filePath) => {
  if (!filePath) return;
  try {
    await fs.promises.unlink(
      path.join(__dirname, "..", filePath.replace(/^\/+/, ""))
    );
  } catch {
    /* ignore */
  }
};

/* ======================================================
   CREATE (JSON ONLY)
   POST /api/textdocs
====================================================== */

router.post("/", async (req, res) => {
  try {
    const { user_id = null, doc_type, fields = {}, notes = null } = req.body;

    if (!doc_type) {
      return res.status(400).json({ message: "doc_type is required" });
    }
    if (typeof fields !== "object") {
      return res.status(400).json({ message: "fields must be object" });
    }

    const q = await pool.query(
      `
      INSERT INTO text_documents (user_id, doc_type, fields, notes)
      VALUES ($1,$2,$3::jsonb,$4)
      RETURNING *
      `,
      [user_id, doc_type, JSON.stringify(fields), notes]
    );

    res.status(201).json(q.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Server error" });
  }
});

/* ======================================================
   CREATE (WITH FILE)
   POST /api/textdocs/upload
====================================================== */

router.post("/upload", upload.single("file"), async (req, res) => {
  try {
    const { user_id = null, doc_type, notes = null } = req.body;
    if (!doc_type) {
      if (req.file) await deleteFile(`/uploads/textdocs/${req.file.filename}`);
      return res.status(400).json({ message: "doc_type is required" });
    }

    const fields = req.body.fields ? safeJSON(req.body.fields) : {};
    if (typeof fields !== "object") {
      if (req.file) await deleteFile(`/uploads/textdocs/${req.file.filename}`);
      return res.status(400).json({ message: "fields must be JSON object" });
    }

    let file_name = null,
      file_mime = null,
      file_size = null,
      file_path = null;

    if (req.file) {
      file_name = req.file.originalname;
      file_mime = req.file.mimetype;
      file_size = req.file.size;
      file_path = `/uploads/textdocs/${req.file.filename}`;
    }

    const q = await pool.query(
      `
      INSERT INTO text_documents
      (user_id, doc_type, fields, notes, file_name, file_mime, file_size, file_path)
      VALUES ($1,$2,$3::jsonb,$4,$5,$6,$7,$8)
      RETURNING *
      `,
      [
        user_id,
        doc_type,
        JSON.stringify(fields),
        notes,
        file_name,
        file_mime,
        file_size,
        file_path,
      ]
    );

    res.status(201).json(q.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Server error" });
  }
});

/* ======================================================
   READ ALL
   GET /api/textdocs
====================================================== */

router.get("/", async (req, res) => {
  try {
    const { q = "", doc_type = "", user_id = "" } = req.query;

    const where = [];
    const vals = [];

    if (doc_type) {
      vals.push(doc_type);
      where.push(`doc_type=$${vals.length}`);
    }

    if (user_id) {
      if (!isUUID(user_id))
        return res.status(400).json({ message: "Invalid user_id" });
      vals.push(user_id);
      where.push(`user_id=$${vals.length}`);
    }

    if (q) {
      vals.push(`%${q}%`);
      where.push(`fields::text ILIKE $${vals.length}`);
    }

    const sql = `
      SELECT * FROM text_documents
      ${where.length ? "WHERE " + where.join(" AND ") : ""}
      ORDER BY created_at DESC
      LIMIT 500
    `;

    const r = await pool.query(sql, vals);
    res.json(r.rows);
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Server error" });
  }
});

/* ======================================================
   READ ONE
   GET /api/textdocs/:id
====================================================== */

router.get("/:id", async (req, res) => {
  const { id } = req.params;
  if (!isUUID(id))
    return res.status(400).json({ message: "Invalid id" });

  const r = await pool.query(
    "SELECT * FROM text_documents WHERE id=$1",
    [id]
  );
  if (!r.rowCount) return res.status(404).json({ message: "Not found" });
  res.json(r.rows[0]);
});

/* ======================================================
   UPDATE (JSON ONLY)
   PUT /api/textdocs/:id
====================================================== */

router.put("/:id", async (req, res) => {
  try {
    const { id } = req.params;
    if (!isUUID(id))
      return res.status(400).json({ message: "Invalid id" });

    const { doc_type, fields, notes, user_id } = req.body;
    const sets = [];
    const vals = [];

    if (user_id !== undefined) {
      vals.push(user_id);
      sets.push(`user_id=$${vals.length}`);
    }
    if (doc_type !== undefined) {
      vals.push(doc_type);
      sets.push(`doc_type=$${vals.length}`);
    }
    if (fields !== undefined) {
      if (typeof fields !== "object")
        return res.status(400).json({ message: "fields must be object" });
      vals.push(JSON.stringify(fields));
      sets.push(`fields=$${vals.length}::jsonb`);
    }
    if (notes !== undefined) {
      vals.push(notes);
      sets.push(`notes=$${vals.length}`);
    }

    if (!sets.length)
      return res.status(400).json({ message: "Nothing to update" });

    vals.push(id);
    const q = await pool.query(
      `
      UPDATE text_documents
      SET ${sets.join(", ")}, updated_at=now()
      WHERE id=$${vals.length}
      RETURNING *
      `,
      vals
    );

    if (!q.rowCount) return res.status(404).json({ message: "Not found" });
    res.json(q.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Server error" });
  }
});

/* ======================================================
   UPDATE WITH FILE
   PUT /api/textdocs/:id/upload
====================================================== */

router.put("/:id/upload", upload.single("file"), async (req, res) => {
  try {
    const { id } = req.params;
    if (!isUUID(id))
      return res.status(400).json({ message: "Invalid id" });

    const old = await pool.query(
      "SELECT file_path FROM text_documents WHERE id=$1",
      [id]
    );
    if (!old.rowCount)
      return res.status(404).json({ message: "Not found" });

    const fields = req.body.fields
      ? safeJSON(req.body.fields)
      : undefined;

    const sets = [];
    const vals = [];

    if (fields !== undefined) {
      if (typeof fields !== "object")
        return res.status(400).json({ message: "fields must be object" });
      vals.push(JSON.stringify(fields));
      sets.push(`fields=$${vals.length}::jsonb`);
    }

    if (req.file) {
      vals.push(req.file.originalname);
      sets.push(`file_name=$${vals.length}`);
      vals.push(req.file.mimetype);
      sets.push(`file_mime=$${vals.length}`);
      vals.push(req.file.size);
      sets.push(`file_size=$${vals.length}`);
      vals.push(`/uploads/textdocs/${req.file.filename}`);
      sets.push(`file_path=$${vals.length}`);
    }

    sets.push(`updated_at=now()`);
    vals.push(id);

    const q = await pool.query(
      `
      UPDATE text_documents
      SET ${sets.join(", ")}
      WHERE id=$${vals.length}
      RETURNING *
      `,
      vals
    );

    if (req.file && old.rows[0].file_path) {
      await deleteFile(old.rows[0].file_path);
    }

    res.json(q.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: "Server error" });
  }
});

/* ======================================================
   DELETE
   DELETE /api/textdocs/:id
====================================================== */

router.delete("/:id", async (req, res) => {
  const { id } = req.params;
  if (!isUUID(id))
    return res.status(400).json({ message: "Invalid id" });

  const r = await pool.query(
    "SELECT file_path FROM text_documents WHERE id=$1",
    [id]
  );
  if (!r.rowCount) return res.status(404).json({ message: "Not found" });

  await pool.query("DELETE FROM text_documents WHERE id=$1", [id]);
  await deleteFile(r.rows[0].file_path);

  res.json({ ok: true, id });
});

module.exports = router;
