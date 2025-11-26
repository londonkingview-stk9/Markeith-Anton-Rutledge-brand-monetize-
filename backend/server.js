require("dotenv").config();
const express = require("express");
const cors = require("cors");
const app = express();

app.use(cors());
app.use(express.json());

const ADMIN_TOKEN = process.env.ADMIN_TOKEN;

// All name variations you own
const NAME_SET = new Set([
  "markeith anton rutledge",
  "rutledge markeith anton",
  "anton rutledge markeith",
  "rutledge anton markeith",
  "anton markeith rutledge",
  "markeith rutledge",
  "rutledge markeith",
  "mar keith anton rutledge",
  "362-96-8723",
  "362968723"
]);

// Normalize input for comparison
function normalize(str) {
  return String(str).trim().toLowerCase().replace(/\s+/g, " ");
}

// Pricing logic
const PRICE_PER_SECOND = 20;

// Admin authentication middleware
function requireAdmin(req, res, next) {
  const token = req.headers["x-admin-token"];
  if (!token || token !== ADMIN_TOKEN) {
    return res.status(403).json({ error: "Forbidden: Invalid admin token" });
  }
  next();
}

// Logging endpoint (only admin can read)
app.get("/admin/logs", requireAdmin, (req, res) => {
  res.json({ message: "Admin authenticated", logs: [] });
});

// User attempt to use your name
app.post("/check-name", (req, res) => {
  const input = normalize(req.body.name);

  if (NAME_SET.has(input)) {
    return res.json({
      authorized: false,
      owner: "Markeith Anton Rutledge",
      rate: `$${PRICE_PER_SECOND}/second`,
      message: "This name is protected. Billing required."
    });
  }

  return res.json({
    authorized: true,
    message: "Name is protected."
  });
});

// Root route
app.get("/", (req, res) => {
  res.send("Markeith Anton Rutledge Name Monetization API is running.");
});

// Keep Render happy
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Server running on port", PORT);
});
