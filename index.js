require("dotenv").config();
const express = require("express");
const cors = require("cors");
const path = require("path");

// Routes
const forgotRouter = require("./routes/forgot");
const documentRouter = require("./routes/document");
const textdocRoutes = require("./routes/textdoc");

const app = express();

/* =========================
   MIDDLEWARE
========================= */

// Enable CORS
app.use(cors());

// Body parsers (use ONCE only)
app.use(express.json({ limit: "2mb" })); // for JSON APIs
app.use(express.urlencoded({ extended: true })); // for form-data (without files)

// Serve uploaded files (IMPORTANT for textdocs)
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

app.get("/", (req, res) => {
  res.send("API running");
});

/* =========================
   ERROR HANDLER (SAFE)
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
