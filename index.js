require("dotenv").config();

const express = require("express");
const cors = require("cors");
const path = require("path");

// Routes
const forgotRouter = require("./routes/forgot");
const documentRouter = require("./routes/document");
const textdocRoutes = require("./routes/textdoc");

// ✅ Footer Route (ADDED)
const footerRoutes = require("./routes/footer");
const adminRoutes = require("./routes/admin");


const app = express();

/* =========================
   MIDDLEWARE
========================= */

// ✅ Body parsers (ONLY ONCE)
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

// ✅ Serve uploaded files
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// ✅ CORS (CRASH-PROOF)
const allowedOrigins = [
  process.env.FRONTEND_URL, // e.g. https://your-vercel-app.vercel.app
  "http://localhost:3000",
  "http://localhost:5173",
].filter(Boolean);

app.use(
  cors({
    origin: (origin, cb) => {
      // allow requests with no origin (Postman, server-to-server)
      if (!origin) return cb(null, true);

      // allow if in list
      if (allowedOrigins.includes(origin)) return cb(null, true);

      // ❌ IMPORTANT: Do NOT throw error here (can crash some setups)
      return cb(null, false);
    },
    credentials: true,
  })
);

/* =========================
   ROUTES
========================= */

app.use("/api/auth", require("./routes/auth"));
app.use("/api/auth/forgot", forgotRouter);
app.use("/api/documents", documentRouter);
app.use("/api/textdocs", textdocRoutes);

// ✅ Footer API (ADDED)
app.use("/api/footer", footerRoutes);

app.use("/admin", adminRoutes);

/* =========================
   HEALTH CHECK
========================= */

app.get("/", (req, res) => res.send("API running ✅"));

app.get("/health", (req, res) =>
  res.json({ ok: true, time: new Date().toISOString() })
);

/* =========================
   ERROR HANDLER
========================= */
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ message: err.message || "Internal Server Error" });
});

/* =========================
   PROCESS SAFETY LOGS
========================= */
process.on("unhandledRejection", (reason) => {
  console.error("UNHANDLED REJECTION:", reason);
});
process.on("uncaughtException", (err) => {
  console.error("UNCAUGHT EXCEPTION:", err);
});

/* =========================
   START SERVER
========================= */

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`✅ Server started on port ${PORT}`);
});
