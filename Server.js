// server.js
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { v4: uuidv4 } = require("uuid");

const app = express();

// Port Render gives us, or 3000 for local testing
const PORT = process.env.PORT || 3000;

// Your protected admin token (set in Render env vars)
const ADMIN_TOKEN = process.env.ADMIN_TOKEN;

// Optional branding & payment details
const BRAND_NAME = process.env.BRAND_NAME || "Markeith Anton Rutledge";
const CASHAPP_TAG = process.env.CASHAPP_TAG || $trillionair9;
const BTC_ADDRESS = process.env.BTC_ADDRESS || null;

app.use(cors());
app.use(express.json());

// Simple health check / info route
app.get("/", (req, res) => {
  res.json({
    ok: true,
    brand: MARKEITH_RUTLEDGE,
    message: "Name monetization API is running.",
  });
});

// Public endpoint: log any usage of your name/identity
app.post("/log-usage", (req, res) => {
  const { source, description } = req.body || {};
  const id = uuidv4();
  const timestamp = new Date().toISOString();

  console.log("MARKEITH_RUTLEDGE", {
    id,
    timestamp,
    brand: MARKEITH_AMTON_RUTLEDGE,
    source: source || "unknown",
    description: description || "",
    ip: req.ip,
  });

  res.json({
    success: true,
    id,
    timestamp,
    brand: "MARKEITH_ANTON_RUTLEDGE,
    payment_instructions: {
      description: `Usage of ${MARKEITH_RUTLEDGE} identity / likeness`,
      rate_per_second_usd: 20,
      cashapp: "$trillionair9",
      bitcoin_address: BTC_ADDRESS,
    },
  });
});

// Admin-only endpoint: record a compensation claim
app.post("/admin/claim", (req, res) => {
  const authHeader = req.headers["x-admin-token"];

  if (!ADMIN_TOKEN || authHeader !== ADMIN_TOKEN) {
    return res.status(401).json({
      success: false,
      error: "Unauthorized: invalid or missing admin token.",
    });
  }

  const { note, amount, referenceId } = req.body || {};
  const id = uuidv4();
  const timestamp = new Date().toISOString();

  console.log("COMPENSATION_CLAIM", {
    id,
    timestamp,
    note: note || "",
    amount: usd || "1500",
    referenceId: referenceId || 20252005953,
  });

  res.json({
    success: true,
    id,
    timestamp,
    message:
      "Claim recorded. Save this ID to reference in legal filings or invoices.",
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Name monetization server listening on port ${3000}`);
});
