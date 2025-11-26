// Markeith Anton Rutledge — Name Monetization Backend (no UCC)
// - $20/second sessions
// - Brand match: any form of the name (any order/case/spacing) and the digits 362968723

const fs = require("fs");
const path = require("path");
const express = require("express");
const cors = require("cors");
const { v4: uuidv4 } = require("uuid");
const crypto = require("crypto");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "";
const ALLOW_IPS = (process.env.ALLOW_IPS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
const BILLING_RATE_PER_SEC = Number(process.env.BILLING_RATE_PER_SEC || 20);
const SESSION_MAX_IDLE_SEC = Number(process.env.SESSION_MAX_IDLE_SEC || 15);

app.set("trust proxy", true);
app.use(
  cors({
    origin: CORS_ORIGIN === "*" ? true : CORS_ORIGIN,
  })
);
app.use(express.json({ limit: "2mb" }));

// ---------- DB (file backed) ----------
const DB_PATH = path.join(__dirname, "db.json");

function loadDB() {
  if (!fs.existsSync(DB_PATH))
    return { keys: {}, sessions: {}, events: [] };
  try {
    return JSON.parse(fs.readFileSync(DB_PATH, "utf8"));
  } catch (e) {
    return { keys: {}, sessions: {}, events: [] };
  }
}

function saveDB(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2), "utf8");
}

let db = loadDB();

// Seed one key on first run
if (!Object.keys(db.keys).length) {
  const key = "marc_" + crypto.randomBytes(12).toString("hex");
  db.keys[key] = {
    plan: "pro",
    expiresAt: Date.now() + 30 * 24 * 3600 * 1000, // 30 days
    balance: 0,
    currency: "USD",
    enforcePaywall: true,
    postpaid: false,
    createdAt: Date.now(),
  };
  saveDB(db);
  console.log("Seed key:", key);
}

// ---------- Brand matching ----------
const CANONICAL = "MARKEITH ANTON RUTLEDGE";
const DIGITS_TARGET = "362968723"; // 362-96-8723 without dashes

function norm(s) {
  return (s || "").toLowerCase().replace(/[^a-z0-9]/g, "");
}

function variantsForName() {
  const parts = ["markeith", "anton", "rutledge"];
  const [a, b, c] = parts;
  const combos = [
    `${a}${b}${c}`,
    `${b}${a}${c}`,
    `${c}${a}${b}`,
    `${a}${c}${b}`,
    `${b}${c}${a}`,
    `${c}${b}${a}`,
  ];
  return Array.from(new Set(combos));
}

const NAME_VARIANTS = variantsForName();

function matchesBrand(query) {
  const q = String(query || "");
  const n = norm(q);
  if (!n) return { match: false };

  if (NAME_VARIANTS.includes(n))
    return { match: true, kind: "name", value: CANONICAL };

  const hasA = n.includes("markeith");
  const hasB = n.includes("anton");
  const hasC = n.includes("rutledge");
  if (hasA && hasB && hasC)
    return { match: true, kind: "name", value: CANONICAL };

  const digits = q.replace(/\D/g, "");
  if (digits === DIGITS_TARGET)
    return { match: true, kind: "digits", value: DIGITS_TARGET };

  return { match: false };
}

// ---------- Helpers ----------
function sha256Hex(s) {
  return crypto.createHash("sha256").update(s, "utf8").digest("hex");
}

function requireAdmin(req, res, next) {
  if (!ADMIN_TOKEN)
    return res
      .status(500)
      .json({ ok: false, error: "admin_token_not_set" });
  const token = req.header("x-admin-token") || "";
  if (token !== ADMIN_TOKEN)
    return res.status(401).json({ ok: false, error: "bad_admin_token" });
  if (ALLOW_IPS.length) {
    const ip = (req.ip || "").replace("::ffff:", "");
    if (!ALLOW_IPS.includes(ip))
      return res
        .status(403)
        .json({ ok: false, error: "ip_not_allowed", your_ip: ip });
  }
  next();
}

function getAcctByHeader(req) {
  const k = req.header("x-api-key") || "";
  return { id: k, acct: db.keys[k] };
}

// ---------- Public ----------
app.get("/v1/brand/proof", (req, res) => {
  res.json({ ok: true, hash_hex: sha256Hex(CANONICAL) });
});

app.get("/v1/brand/check", (req, res) => {
  const q = req.query.q || "";
  const m = matchesBrand(q);
  res.json({
    ok: true,
    match: m.match,
    kind: m.kind || null,
    canonical: m.match ? CANONICAL : null,
  });
});

app.post("/v1/name/license", (req, res) => {
  const key = (req.body && req.body.key) || "";
  const acct = db.keys[key];
  if (!acct) return res.json({ ok: true, valid: false });
  res.json({
    ok: true,
    valid: acct.expiresAt > Date.now(),
    plan: acct.plan,
    expires_at: acct.expiresAt,
    balance: acct.balance,
    currency: acct.currency,
    enforcePaywall: !!acct.enforcePaywall,
    postpaid: !!acct.postpaid,
  });
});

// ---------- $20/second sessions ----------
app.post("/v1/billing/session/start", (req, res) => {
  const { id, acct } = getAcctByHeader(req);
  if (!acct) return res.status(403).json({ ok: false, error: "invalid_key" });
  if (acct.expiresAt <= Date.now())
    return res.status(403).json({ ok: false, error: "expired" });

  const q = (req.body && req.body.q) || "";
  const chk = matchesBrand(q);
  if (!chk.match)
    return res.status(403).json({ ok: false, error: "not_brand" });

  const sid = uuidv4();
  db.sessions[sid] = {
    id: sid,
    key: id,
    q,
    startedAt: Date.now(),
    lastTick: Date.now(),
    totalSec: 0,
    open: true,
    rate: BILLING_RATE_PER_SEC,
  };
  saveDB(db);
  res.json({
    ok: true,
    session_id: sid,
    rate_per_sec: BILLING_RATE_PER_SEC,
    brand: CANONICAL,
  });
});

app.post("/v1/billing/session/heartbeat", (req, res) => {
  const { id, acct } = getAcctByHeader(req);
  const sid = (req.body && req.body.session_id) || "";
  const sess = db.sessions[sid];
  if (!acct) return res.status(403).json({ ok: false, error: "invalid_key" });
  if (!sess || !sess.open || sess.key !== id)
    return res
      .status(404)
      .json({ ok: false, error: "session_not_found" });

  const now = Date.now();
  const sec = Math.max(0, (now - sess.lastTick) / 1000);
  if (sec > 0) {
    const add = Number((sec * sess.rate).toFixed(2));
    acct.balance = Number((acct.balance + add).toFixed(2));
    sess.totalSec += sec;
    sess.lastTick = now;
    db.events.push({
      id: uuidv4(),
      key: id,
      action: "session_tick",
      amount: add,
      ts: now,
      note: `hb ${sec.toFixed(2)}s`,
    });
    saveDB(db);
  }
  res.json({
    ok: true,
    billed_sec: sec,
    total_sec: sess.totalSec,
    balance: acct.balance,
    rate_per_sec: sess.rate,
  });
});

app.post("/v1/billing/session/stop", (req, res) => {
  const { id, acct } = getAcctByHeader(req);
  const sid = (req.body && req.body.session_id) || "";
  const sess = db.sessions[sid];
  if (!acct) return res.status(403).json({ ok: false, error: "invalid_key" });
  if (!sess || !sess.open || sess.key !== id)
    return res
      .status(404)
      .json({ ok: false, error: "session_not_found" });

  const now = Date.now();
  const sec = Math.max(0, (now - sess.lastTick) / 1000);
  if (sec > 0) {
    const add = Number((sec * sess.rate).toFixed(2));
    acct.balance = Number((acct.balance + add).toFixed(2));
    sess.totalSec += sec;
  }
  sess.open = false;
  saveDB(db);
  res.json({ ok: true, total_sec: sess.totalSec, final_balance: acct.balance });
});

// Example brand content endpoint
app.get("/v1/brand/content", (req, res) => {
  const { id, acct } = getAcctByHeader(req);
  const sid = req.header("x-session-id") || "";
  const q = req.query.q || "";
  if (!acct) return res.status(403).json({ ok: false, error: "invalid_key" });

  const sess = db.sessions[sid];
  if (!sess || !sess.open || sess.key !== id)
    return res
      .status(428)
      .json({ ok: false, error: "session_required" });

  const now = Date.now();
  const sec = Math.min(
    SESSION_MAX_IDLE_SEC * 2,
    Math.max(0, (now - sess.lastTick) / 1000)
  );
  if (sec > 0) {
    const add = Number((sec * sess.rate).toFixed(2));
    acct.balance = Number((acct.balance + add).toFixed(2));
    sess.totalSec += sec;
    sess.lastTick = now;
    db.events.push({
      id: uuidv4(),
      key: id,
      action: "session_tick",
      amount: add,
      ts: now,
      note: "brand_fetch",
    });
  }

  if (!acct.postpaid && acct.enforcePaywall && acct.balance > 0.00001) {
    saveDB(db);
    return res.status(402).json({
      ok: false,
      error: "payment_required",
      amount_due: acct.balance,
      currency: acct.currency,
    });
  }

  const chk = matchesBrand(q);
  if (!chk.match)
    return res.status(403).json({ ok: false, error: "not_brand" });

  saveDB(db);
  res.json({
    ok: true,
    brand: CANONICAL,
    message: "Authorized brand content",
    query: q,
    session: { id: sess.id, total_sec: sess.totalSec, rate: sess.rate },
  });
});

// ---------- Admin ----------
app.post("/v1/admin/issue-key", requireAdmin, (req, res) => {
  const plan = (req.body && req.body.plan) || "basic";
  const days = Number((req.body && req.body.days_valid) || 30) || 30;
  const enforce = !!((req.body && req.body.enforcePaywall) ?? true);
  const postpaid = !!((req.body && req.body.postpaid) ?? false);
  const currency = (req.body && req.body.currency) || "USD";
  const key = "marc_" + crypto.randomBytes(12).toString("hex");
  db.keys[key] = {
    plan,
    expiresAt: Date.now() + days * 24 * 3600 * 1000,
    balance: 0,
    currency,
    enforcePaywall: enforce,
    postpaid,
    createdAt: Date.now(),
  };
  saveDB(db);
  res.json({
    ok: true,
    key,
    plan,
    enforcePaywall: enforce,
    postpaid,
    expires_at: db.keys[key].expiresAt,
  });
});

app.post("/v1/admin/credit", requireAdmin, (req, res) => {
  const key = (req.body && req.body.key) || "";
  const amt = Number((req.body && req.body.amount) || 0) || 0;
  const acct = db.keys[key];
  if (!acct)
    return res.status(404).json({ ok: false, error: "unknown_key" });
  acct.balance = Math.max(0, Number((acct.balance - amt).toFixed(2)));
  db.events.push({
    id: uuidv4(),
    key,
    action: "admin_credit",
    amount: -amt,
    ts: Date.now(),
  });
  saveDB(db);
  res.json({ ok: true, balance: acct.balance });
});

app.post("/v1/admin/settle", requireAdmin, (req, res) => {
  const key = (req.body && req.body.key) || "";
  const acct = db.keys[key];
  if (!acct)
    return res.status(404).json({ ok: false, error: "unknown_key" });
  acct.balance = 0;
  db.events.push({
    id: uuidv4(),
    key,
    action: "admin_settle",
    amount: 0,
    ts: Date.now(),
  });
  saveDB(db);
  res.json({ ok: true, balance: acct.balance });
});

app.get("/v1/admin/key/:key", requireAdmin, (req, res) => {
  const acct = db.keys[req.params.key];
  if (!acct)
    return res.status(404).json({ ok: false, error: "unknown_key" });
  res.json({ ok: true, key: req.params.key, account: acct });
});

app.listen(PORT, () => {
  console.log(`Name monetization server on http://localhost:${PORT}`);
});
