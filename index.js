require("dotenv").config();
const express = require("express");
const cors = require("cors");
const path = require("path");

// ✅ DB connection (FIXED PATH)
const pool = require("./db");


// Routes
const forgotRouter = require("./routes/forgot");
const documentRouter = require("./routes/document");
const textdocRoutes = require("./routes/textdoc");

const app = express();

/* =========================
   MIDDLEWARE
========================= */

app.use(cors());

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

app.use(
  "/uploads",
  express.static(path.join(__dirname, "uploads"))
);

/* =========================
   ROUTES
========================= */

app.use("/api/auth", require("./routes/auth"));
app.use("/api/auth/forgot", forgotRouter);
app.use("/api/documents", documentRouter);
app.use("/api/textdocs", textdocRoutes);

/* =========================
   HEALTH CHECK
========================= */

app.get("/", async (req, res) => {
  try {
    await pool.query("SELECT 1"); // ✅ DB keep-alive check
    res.send("API running");
  } catch (err) {
    res.status(500).send("DB connection failed");
  }
});

/* =========================
   ERROR HANDLER
========================= */

app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ message: "Internal Server Error" });
});

/* =========================
   START SERVER
========================= */

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`✅ Server started on port ${PORT}`);
});
