const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const mime = require("mime-types");
const pool = require("../db"); // ✅ as you requested

const router = express.Router();

/* =======================
   ✅ AUTH (REQUIRED)
   You must have login middleware that sets req.user = { id: ... }
   If you don't, this fallback uses header: x-user-id (temporary only)
======================= */
function requireAuth(req, res, next) {
  const idFromReqUser = req.user?.id || req.user?.user_id;
  const idFromHeader = req.headers["x-user-id"]; // fallback (temporary)

  const userId = idFromReqUser || idFromHeader;
  if (!userId) return res.status(401).json({ message: "Unauthorized" });

  req.authUserId = userId;
  next();
}

/* =======================
   Local storage settings
======================= */
const UPLOAD_DIR = path.join(process.cwd(), "uploads", "documents");
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

function safeName(name) {
  return String(name || "")
    .replace(/[^\w.\- ]+/g, "_")
    .replace(/\s+/g, "_")
    .slice(0, 120);
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname || "");
    const base = safeName(path.basename(file.originalname || "file", ext));
    const unique = `${Date.now()}_${crypto.randomBytes(6).toString("hex")}`;
    cb(null, `${base}_${unique}${ext}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 200 * 1024 * 1024 }, // 200MB
});

/* =======================
   Helpers
======================= */
function sha256File(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash("sha256");
    const stream = fs.createReadStream(filePath);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("error", reject);
    stream.on("end", () => resolve(hash.digest("hex")));
  });
}

function getFileExt(originalName, mimeType) {
  const extFromName = path.extname(originalName || "").replace(".", "").toLowerCase();
  if (extFromName) return extFromName;
  const extFromMime = mime.extension(mimeType || "");
  return (extFromMime || "bin").toLowerCase();
}

async function fileExists(p) {
  try {
    await fs.promises.access(p);
    return true;
  } catch {
    return false;
  }
}

async function deleteLocalFile(p) {
  if (!p) return;
  if (!(await fileExists(p))) return;
  try {
    await fs.promises.unlink(p);
  } catch (e) {
    console.error("FILE DELETE ERROR:", e.message);
  }
}

/* =========================================================
   ✅ POST /api/documents
   Upload document (only logged-in user)
   multipart/form-data:
     document_title (required)
     short_desc (optional)
     file (required)
========================================================= */
router.post("/", requireAuth, upload.single("file"), async (req, res) => {
  let savedPath = null;

  try {
    const user_id = req.authUserId;

    const document_title = String(req.body.document_title || "").trim();
    const short_desc = req.body.short_desc ? String(req.body.short_desc).trim() : null;

    if (!document_title) {
      if (req.file?.path) await deleteLocalFile(req.file.path);
      return res.status(400).json({ message: "document_title is required" });
    }
    if (!req.file) {
      return res.status(400).json({ message: "file is required" });
    }

    savedPath = req.file.path;
    const file_path = savedPath;
    const original_name = req.file.originalname;
    const mime_type = req.file.mimetype || mime.lookup(req.file.filename) || "application/octet-stream";
    const file_ext = getFileExt(original_name, mime_type);
    const file_size_bytes = Number(req.file.size || 0);

    const checksum_sha256 = await sha256File(savedPath);

    // ✅ Duplicate check ONLY FOR SAME USER (not global)
    const dup = await pool.query(
      `SELECT id FROM document_random WHERE user_id=$1 AND checksum_sha256=$2 LIMIT 1`,
      [user_id, checksum_sha256]
    );
    if (dup.rows.length > 0) {
      await deleteLocalFile(savedPath);
      return res.status(409).json({ message: "Same document already uploaded (duplicate)" });
    }

    const result = await pool.query(
      `INSERT INTO document_random
        (user_id, document_title, short_desc, file_path, original_name, mime_type, file_ext, file_size_bytes, checksum_sha256)
       VALUES
        ($1,$2,$3,$4,$5,$6,$7,$8,$9)
       RETURNING *`,
      [
        user_id,
        document_title,
        short_desc,
        file_path,
        original_name,
        mime_type,
        file_ext,
        file_size_bytes,
        checksum_sha256,
      ]
    );

    return res.status(201).json({ message: "Document uploaded", document: result.rows[0] });
  } catch (err) {
    console.error("UPLOAD ERROR:", err);
    if (savedPath) await deleteLocalFile(savedPath);
    return res.status(500).json({ message: "Server error" });
  }
});

/* =========================================================
   ✅ GET /api/documents
   List only logged-in user's documents
   Optional: ?q=
========================================================= */
router.get("/", requireAuth, async (req, res) => {
  try {
    const user_id = req.authUserId;
    const q = String(req.query.q || "").trim().toLowerCase();

    const result = q
      ? await pool.query(
          `SELECT * FROM document_random
           WHERE user_id=$1 AND LOWER(document_title) LIKE '%' || $2 || '%'
           ORDER BY uploaded_at DESC`,
          [user_id, q]
        )
      : await pool.query(
          `SELECT * FROM document_random
           WHERE user_id=$1
           ORDER BY uploaded_at DESC`,
          [user_id]
        );

    return res.json(result.rows);
  } catch (err) {
    console.error("GET DOCS ERROR:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

/* =========================================================
   ✅ GET /api/documents/:id
   Get single document metadata (only owner)
========================================================= */
router.get("/:id", requireAuth, async (req, res) => {
  try {
    const user_id = req.authUserId;
    const { id } = req.params;

    const result = await pool.query(
      `SELECT * FROM document_random WHERE id=$1 AND user_id=$2`,
      [id, user_id]
    );
    if (result.rows.length === 0) return res.status(404).json({ message: "Document not found" });

    return res.json(result.rows[0]);
  } catch (err) {
    console.error("GET DOC ERROR:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

/* =========================================================
   ✅ GET /api/documents/:id/download
   Download (only owner)
========================================================= */
router.get("/:id/download", requireAuth, async (req, res) => {
  try {
    const user_id = req.authUserId;
    const { id } = req.params;

    const result = await pool.query(
      `SELECT * FROM document_random WHERE id=$1 AND user_id=$2`,
      [id, user_id]
    );
    if (result.rows.length === 0) return res.status(404).json({ message: "Document not found" });

    const doc = result.rows[0];
    const p = doc.file_path;

    if (!(await fileExists(p))) {
      return res.status(404).json({ message: "File missing on server storage" });
    }

    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${encodeURIComponent(doc.original_name)}"`
    );
    res.setHeader("Content-Type", doc.mime_type || "application/octet-stream");

    return res.sendFile(p);
  } catch (err) {
    console.error("DOWNLOAD ERROR:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

/* =========================================================
   ✅ PUT /api/documents/:id
   Update title/desc OR replace file (only owner)
   multipart/form-data:
     document_title (optional)
     short_desc (optional)
     file (optional)
========================================================= */
router.put("/:id", requireAuth, upload.single("file"), async (req, res) => {
  let newSavedPath = null;

  try {
    const user_id = req.authUserId;
    const { id } = req.params;

    // ✅ must be owner
    const existingRes = await pool.query(
      `SELECT * FROM document_random WHERE id=$1 AND user_id=$2`,
      [id, user_id]
    );
    if (existingRes.rows.length === 0) {
      if (req.file?.path) await deleteLocalFile(req.file.path);
      return res.status(404).json({ message: "Document not found" });
    }
    const existing = existingRes.rows[0];

    const document_title =
      req.body.document_title !== undefined ? String(req.body.document_title).trim() : null;
    const short_desc =
      req.body.short_desc !== undefined ? String(req.body.short_desc).trim() : null;

    let file_path = null;
    let original_name = null;
    let mime_type = null;
    let file_ext = null;
    let file_size_bytes = null;
    let checksum_sha256 = null;

    if (req.file) {
      newSavedPath = req.file.path;

      file_path = newSavedPath;
      original_name = req.file.originalname;
      mime_type = req.file.mimetype || mime.lookup(req.file.filename) || "application/octet-stream";
      file_ext = getFileExt(original_name, mime_type);
      file_size_bytes = Number(req.file.size || 0);
      checksum_sha256 = await sha256File(newSavedPath);

      // ✅ duplicate check for SAME USER only
      const dup = await pool.query(
        `SELECT id FROM document_random
         WHERE user_id=$1 AND checksum_sha256=$2 AND id<>$3
         LIMIT 1`,
        [user_id, checksum_sha256, id]
      );
      if (dup.rows.length > 0) {
        await deleteLocalFile(newSavedPath);
        return res.status(409).json({ message: "Duplicate document already exists" });
      }
    }

    const updated = await pool.query(
      `UPDATE document_random SET
        document_title  = COALESCE($1, document_title),
        short_desc      = COALESCE($2, short_desc),
        file_path       = COALESCE($3, file_path),
        original_name   = COALESCE($4, original_name),
        mime_type       = COALESCE($5, mime_type),
        file_ext        = COALESCE($6, file_ext),
        file_size_bytes = COALESCE($7, file_size_bytes),
        checksum_sha256 = COALESCE($8, checksum_sha256)
       WHERE id=$9 AND user_id=$10
       RETURNING *`,
      [
        document_title,
        short_desc,
        file_path,
        original_name,
        mime_type,
        file_ext,
        file_size_bytes,
        checksum_sha256,
        id,
        user_id,
      ]
    );

    // ✅ delete old file if replaced
    if (req.file && existing.file_path && existing.file_path !== file_path) {
      await deleteLocalFile(existing.file_path);
    }

    return res.json({ message: "Updated successfully", document: updated.rows[0] });
  } catch (err) {
    console.error("UPDATE DOC ERROR:", err);
    if (newSavedPath) await deleteLocalFile(newSavedPath);
    return res.status(500).json({ message: "Server error" });
  }
});

/* =========================================================
   ✅ DELETE /api/documents/:id
   Delete (only owner) + delete local file
========================================================= */
router.delete("/:id", requireAuth, async (req, res) => {
  try {
    const user_id = req.authUserId;
    const { id } = req.params;

    const existingRes = await pool.query(
      `SELECT * FROM document_random WHERE id=$1 AND user_id=$2`,
      [id, user_id]
    );
    if (existingRes.rows.length === 0) return res.status(404).json({ message: "Document not found" });

    const doc = existingRes.rows[0];

    const del = await pool.query(
      `DELETE FROM document_random WHERE id=$1 AND user_id=$2 RETURNING id`,
      [id, user_id]
    );

    await deleteLocalFile(doc.file_path);

    return res.json({ message: "Deleted successfully", id: del.rows[0].id });
  } catch (err) {
    console.error("DELETE DOC ERROR:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

module.exports = router;
