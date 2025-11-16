# Markeith-Anton-Rutledge-brand-monetize-
Markeith Anton Rutledge brand monetization- $20/sec and sessions and name verification 
/backend
/app-droidscript
/website{
  "name": "rutledge-name-monetization",
  "version": "1.0.0",
  "description": "Monetize access to the Markeith Anton Rutledge brand via $20/sec metered sessions.",
  "main": "server.js",
  "scripts": { "start": "node server.js" },
  "dependencies": {
    "cors": "^2.8.5",
    "dotenv": "^16.4.5",
    "express": "^4.19.2",
    "uuid": "^9.0.1"
  }
}
// Markeith Anton Rutledge — Name Monetization Backend (no UCC)
// - $20/second sessions
// - Private brand: only your name (any order/case/spacing) and the digits 362968723 match
// - Admin routes locked by token + your IP allow-list

const fs = require('fs');
const path = require('path');
const express = require('express');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';
const ALLOW_IPS = (process.env.ALLOW_IPS || '').split(',').map(s=>s.trim()).filter(Boolean);
const BILLING_RATE_PER_SEC = Number(process.env.BILLING_RATE_PER_SEC || 20);
const SESSION_MAX_IDLE_SEC = Number(process.env.SESSION_MAX_IDLE_SEC || 15);

app.set('trust proxy', true);
app.use(cors({ origin: CORS_ORIGIN === '*' ? true : CORS_ORIGIN }));
app.use(express.json({ limit: '2mb' }));

// ---- In-memory store (file-backed) ----
const DB_PATH = path.join(__dirname, 'db.json');
function loadDB(){
  if (!fs.existsSync(DB_PATH)) return { keys:{}, sessions:{}, events:[] };
  try { return JSON.parse(fs.readFileSync(DB_PATH, 'utf8')); }
  catch { return { keys:{}, sessions:{}, events:[] }; }
}
function saveDB(db){ fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2), 'utf8'); }
let db = loadDB();

// Seed one key on first run
if (!Object.keys(db.keys).length){
  const key = 'marc_' + crypto.randomBytes(12).toString('hex');
  db.keys[key] = {
    plan: 'pro',
    expiresAt: Date.now() + 30*24*3600*1000,
    balance: 0,
    currency: 'USD',
    enforcePaywall: true,
    postpaid: false, // set true if you want to allow debt to accrue before blocking
    createdAt: Date.now()
  };
  saveDB(db);
  console.log('Seed key:', key);
}

// ---- Brand matching (name variants & digits) ----
const CANONICAL = 'MARKEITH ANTON RUTLEDGE';
const DIGITS_TARGET = '362968723';            // 362-96-8723 without dashes

// Normalizer: lowercase, remove non-alphanumerics
function norm(s){ return (s||'').toLowerCase().replace(/[^a-z0-9]/g,''); }

// Generate legal variants in different orders automatically
function variantsForName(){
  const parts = ['marKeith','anton','rutledge'].map(p=>p.toLowerCase());
  const [a,b,c] = parts;
  const combos = [
    `${a}${b}${c}`, `${b}${a}${c}`, `${c}${a}${b}`,
    `${a}${c}${b}`, `${b}${c}${a}`, `${c}${b}${a}`
  ];
  return Array.from(new Set(combos));
}
const NAME_VARIANTS = variantsForName(); // all 3! permutations collapsed with no punctuation

function matchesBrand(query){
  const q = String(query||'');
  const n = norm(q);
  if (!n) return { match:false };

  // Name match: equals any normalized permutation OR contains all three parts in any order
  if (NAME_VARIANTS.includes(n)) return { match:true, kind:'name', value: CANONICAL };

  // Containment check (all parts present, any order)
  const hasA = n.includes('markeith');
  const hasB = n.includes('anton');
  const hasC = n.includes('rutledge');
  if (hasA && hasB && hasC) return { match:true, kind:'name', value: CANONICAL };

  // Digits match (with or without dashes)
  const digits = q.replace(/\D/g,'');
  if (digits === DIGITS_TARGET) return { match:true, kind:'digits', value: DIGITS_TARGET };

  return { match:false };
}

// ---- Helpers ----
function sha256Hex(s){ return crypto.createHash('sha256').update(s,'utf8').digest('hex'); }
function requireAdmin(req,res,next){
  if (!ADMIN_TOKEN) return res.status(500).json({ ok:false, error:'admin_token_not_set' });
  const token = req.header('x-admin-token') || '';
  if (token !== ADMIN_TOKEN) return res.status(401).json({ ok:false, error:'bad_admin_token' });
  if (ALLOW_IPS.length){
    const ip = (req.ip || '').replace('::ffff:','');
    if (!ALLOW_IPS.includes(ip)) return res.status(403).json({ ok:false, error:'ip_not_allowed', your_ip: ip });
  }
  next();
}
function getAcctByHeader(req){
  const k = req.header('x-api-key') || '';
  return { id:k, acct: db.keys[k] };
}
function billSeconds(acct, seconds, note){
  const add = Number((seconds * BILLING_RATE_PER_SEC).toFixed(2));
  acct.balance = Number((acct.balance + add).toFixed(2));
  db.events.push({ id: uuidv4(), key: Object.keys(db.keys).find(k=>db.keys[k]===acct) || 'unknown', action:'session_tick', amount:add, ts: Date.now(), note });
}

// ---- Public endpoints ----
app.get('/v1/brand/proof', (req,res)=> {
  res.json({ ok:true, hash_hex: sha256Hex(CANONICAL) });
});

app.get('/v1/brand/check', (req,res)=>{
  const q = req.query.q || '';
  const m = matchesBrand(q);
  res.json({ ok:true, match: m.match, kind: m.kind || null, canonical: m.match ? CANONICAL : null });
});

app.post('/v1/name/license', (req,res)=>{
  const key = (req.body && req.body.key) || '';
  const acct = db.keys[key];
  if (!acct) return res.json({ ok:true, valid:false });
  res.json({
    ok:true, valid: acct.expiresAt > Date.now(),
    plan: acct.plan, expires_at: acct.expiresAt,
    balance: acct.balance, currency: acct.currency,
    enforcePaywall: !!acct.enforcePaywall, postpaid: !!acct.postpaid
  });
});

// ---- $20/sec metered sessions ----
app.post('/v1/billing/session/start', (req,res)=>{
  const { id, acct } = getAcctByHeader(req);
  if (!acct) return res.status(403).json({ ok:false, error:'invalid_key' });
  if (acct.expiresAt <= Date.now()) return res.status(403).json({ ok:false, error:'expired' });

  const q = (req.body && req.body.q) || '';       // what they’re accessing
  const chk = matchesBrand(q);
  if (!chk.match) return res.status(403).json({ ok:false, error:'not_brand' });

  const sid = uuidv4();
  db.sessions[sid] = {
    id: sid, key: id, q, startedAt: Date.now(), lastTick: Date.now(),
    totalSec: 0, open: true, rate: BILLING_RATE_PER_SEC
  };
  saveDB(db);
  res.json({ ok:true, session_id: sid, rate_per_sec: BILLING_RATE_PER_SEC, brand: CANONICAL });
});

app.post('/v1/billing/session/heartbeat', (req,res)=>{
  const { id, acct } = getAcctByHeader(req);
  const sid = (req.body && req.body.session_id) || '';
  const sess = db.sessions[sid];
  if (!acct) return res.status(403).json({ ok:false, error:'invalid_key' });
  if (!sess || !sess.open || sess.key !== id) return res.status(404).json({ ok:false, error:'session_not_found' });

  const now = Date.now();
  const sec = Math.max(0, (now - sess.lastTick)/1000);
  if (sec > 0){
    const add = Number((sec * sess.rate).toFixed(2));
    acct.balance = Number((acct.balance + add).toFixed(2));
    sess.totalSec += sec;
    sess.lastTick = now;
    db.events.push({ id: uuidv4(), key: id, action:'session_tick', amount:add, ts: now, note: `hb ${sec.toFixed(2)}s` });
    saveDB(db);
  }
  res.json({ ok:true, billed_sec: sec, total_sec: sess.totalSec, balance: acct.balance, rate_per_sec: sess.rate });
});

app.post('/v1/billing/session/stop', (req,res)=>{
  const { id, acct } = getAcctByHeader(req);
  const sid = (req.body && req.body.session_id) || '';
  const sess = db.sessions[sid];
  if (!acct) return res.status(403).json({ ok:false, error:'invalid_key' });
  if (!sess || !sess.open || sess.key !== id) return res.status(404).json({ ok:false, error:'session_not_found' });

  const now = Date.now();
  const sec = Math.max(0, (now - sess.lastTick)/1000);
  if (sec > 0){
    const add = Number((sec * sess.rate).toFixed(2));
    acct.balance = Number((acct.balance + add).toFixed(2));
    sess.totalSec += sec;
  }
  sess.open = false;
  saveDB(db);
  res.json({ ok:true, total_sec: sess.totalSec, final_balance: acct.balance });
});

// Example “brand content” endpoint — blocked unless balance conditions are satisfied
app.get('/v1/brand/content', (req,res)=>{
  const { id, acct } = getAcctByHeader(req);
  const sid = req.header('x-session-id') || '';
  const q = req.query.q || '';
  if (!acct) return res.status(403).json({ ok:false, error:'invalid_key' });

  // enforce session
  const sess = db.sessions[sid];
  if (!sess || !sess.open || sess.key !== id) return res.status(428).json({ ok:false, error:'session_required' });

  // quick tick for elapsed time up to this call
  const now = Date.now();
  const sec = Math.min(SESSION_MAX_IDLE_SEC*2, Math.max(0, (now - sess.lastTick)/1000));
  if (sec > 0){
    const add = Number((sec * sess.rate).toFixed(2));
    acct.balance = Number((acct.balance + add).toFixed(2));
    sess.totalSec += sec;
    sess.lastTick = now;
    db.events.push({ id: uuidv4(), key: id, action:'session_tick', amount:add, ts: now, note:'brand_fetch' });
  }

  // paywall: if prepaid (postpaid=false) and balance > 0, block
  if (!acct.postpaid && acct.enforcePaywall && acct.balance > 0.00001){
    saveDB(db);
    return res.status(402).json({ ok:false, error:'payment_required', amount_due: acct.balance, currency: acct.currency });
  }

  // gate by brand match
  const chk = matchesBrand(q);
  if (!chk.match) return res.status(403).json({ ok:false, error:'not_brand' });

  saveDB(db);
  res.json({ ok:true, brand: CANONICAL, message: "Authorized brand content", query: q, session: { id: sess.id, total_sec: sess.totalSec, rate: sess.rate } });
});

// ---- Admin routes ----
app.post('/v1/admin/issue-key', requireAdmin, (req,res)=>{
  const plan = (req.body && req.body.plan) || 'basic';
  const days = Number((req.body && req.body.days_valid) || 30) || 30;
  const enforce = !!((req.body && req.body.enforcePaywall) ?? true);
  const postpaid = !!((req.body && req.body.postpaid) ?? false);
  const currency = (req.body && req.body.currency) || 'USD';
  const key = 'marc_' + crypto.randomBytes(12).toString('hex');
  db.keys[key] = {
    plan, expiresAt: Date.now() + days*24*3600*1000, balance: 0,
    currency, enforcePaywall: enforce, postpaid, createdAt: Date.now()
  };
  saveDB(db);
  res.json({ ok:true, key, plan, enforcePaywall: enforce, postpaid, expires_at: db.keys[key].expiresAt });
});

app.post('/v1/admin/credit', requireAdmin, (req,res)=>{
  const key = (req.body && req.body.key) || '';
  const amt = Number((req.body && req.body.amount) || 0) || 0;
  const acct = db.keys[key];
  if (!acct) return res.status(404).json({ ok:false, error:'unknown_key' });
  acct.balance = Math.max(0, Number((acct.balance - amt).toFixed(2)));
  db.events.push({ id: uuidv4(), key, action:'admin_credit', amount:-amt, ts: Date.now() });
  saveDB(db);
  res.json({ ok:true, balance: acct.balance });
});

app.post('/v1/admin/settle', requireAdmin, (req,res)=>{
  const key = (req.body && req.body.key) || '';
  const acct = db.keys[key];
  if (!acct) return res.status(404).json({ ok:false, error:'unknown_key' });
  acct.balance = 0;
  db.events.push({ id: uuidv4(), key, action:'admin_settle', amount:0, ts: Date.now() });
  saveDB(db);
  res.json({ ok:true, balance: acct.balance });
});

app.get('/v1/admin/key/:key', requireAdmin, (req,res)=>{
  const acct = db.keys[req.params.key];
  if (!acct) return res.status(404).json({ ok:false, error:'unknown_key' });
  res.json({ ok:true, key: req.params.key, account: acct });
});

// ---- Start ----
app.listen(PORT, ()=> console.log(`Name monetization server on http://localhost:${PORT}`));// DroidScript demo client for the name-monetization backend
var API_BASE = "https://Markeith-Rutledge-URL";
var edtKey, edtQuery, txt, sessionId=null, hbTimer=null;

function OnStart(){
  var lay = app.CreateLayout("linear","VCenter,FillXY");

  edtKey = app.CreateTextEdit("",0.92); edtKey.SetHint("API Key"); lay.AddChild(edtKey);
  edtQuery = app.CreateTextEdit("Markeith  Anton   Rutledge",0.92); lay.AddChild(edtQuery);

  var row = app.CreateLayout("linear","Horizontal,FillX");
  var bStart = app.CreateButton("Start Session",0.45,-1);
  var bStop  = app.CreateButton("Stop Session",0.45,-1);
  row.AddChild(bStart); row.AddChild(bStop); lay.AddChild(row);

  var bFetch = app.CreateButton("Get Brand Content",0.92,-1); lay.AddChild(bFetch);

  txt = app.CreateText("",0.92,0.6,"Multiline,FillX"); lay.AddChild(txt);

  app.AddLayout(lay);
  bStart.SetOnTouch(startSession);
  bStop.SetOnTouch(stopSession);
  bFetch.SetOnTouch(fetchBrand);
}

function set(s){ txt.SetText(s); }
function http(m,p,b,h,cb){
  var x=new XMLHttpRequest(); x.open(m,API_BASE+p,true);
  x.setRequestHeader("Content-Type","application/json");
  if (h) for (var k in h) x.setRequestHeader(k,h[k]);
  x.onreadystatechange=function(){
    if (x.readyState===4){ try{ cb(null,JSON.parse(x.responseText),x.status);}catch(e){cb(e);} }
  };
  x.onerror=function(){ cb(new Error("network_error")); };
  x.send(b?JSON.stringify(b):null);
}

function startSession(){
  var key=edtKey.GetText().trim(); if(!key) return set("Enter key.");
  var q=edtQuery.GetText().trim();
  http("POST","/v1/billing/session/start",{ q:q },{ "x-api-key": key },function(e,r,s){
    if(e||!r||!r.ok) return set("Start error.");
    sessionId=r.session_id; set("Session started @ $"+r.rate_per_sec+"/sec\nID="+sessionId);
    if(hbTimer) clearInterval(hbTimer);
    hbTimer=setInterval(function(){
      http("POST","/v1/billing/session/heartbeat",{ session_id: sessionId },{ "x-api-key": key },function(err,res,st){
        if(err||!res||!res.ok) return;
        set("Billed "+res.billed_sec.toFixed(2)+"s • Total "+res.total_sec.toFixed(2)+"s • Balance $"+res.balance.toFixed(2));
      });
    },3000);
  });
}

function stopSession(){
  var key=edtKey.GetText().trim(); if(!key||!sessionId) return set("No session.");
  if(hbTimer){ clearInterval(hbTimer); hbTimer=null; }
  http("POST","/v1/billing/session/stop",{ session_id: sessionId },{ "x-api-key": key },function(e,r,s){
    if(e||!r||!r.ok) return set("Stop error.");
    set("Stopped. Total "+r.total_sec.toFixed(2)+"s • Final $"+r.final_balance.toFixed(2));
    sessionId=null;
  });
}

function fetchBrand(){
  var key=edtKey.GetText().trim(); var q=edtQuery.GetText().trim();
  if(!key) return set("Enter key."); if(!sessionId) return set("Start a session first.");
  http("GET","/v1/brand/content?q="+encodeURIComponent(q),null,{ "x-api-key": key, "x-session-id": sessionId },function(e,r,s){
    if(s===428) return set("Start a session first.");
    if(s===402) return set("Payment required. Balance due.");
    if(e||!r||!r.ok) return set("Brand fetch error.");
    set("Authorized brand content • Session "+r.session.total_sec.toFixed(2)+"s • Rate $"+r.session.rate+"/sec");
  });
}
