// Divine Admin Panel server
// - WebSocket for pushing events to connected clients on the Divine static site
// - HTTP API for admin actions (PIN-protected) (broadcast + site lockdown admin actions)
// - Public state endpoint for static clients to fetch on load
// - ClientID access control system (bans + access-lockdown + self-unban with PIN)
// - Server-side PIN validation for the static "Access Restricted" gate (/api/auth)
//
// ENV:
//   ADMIN_PIN=.... (required for broadcast + site-lockdown + access admin UI actions)
//   AUTH_PIN=....  (required for /api/auth - "Access Restricted" login PIN)
//   UNBAN_PIN=.... (required for /api/unban on the banned page)
//   DATA_DIR=....  (optional persistent dir)

const path = require("path");
const express = require("express");
const http = require("http");
const { WebSocketServer } = require("ws");

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "256kb" }));

// ---- Config
const ADMIN_PIN = process.env.ADMIN_PIN || "";
if (!ADMIN_PIN) console.warn("WARNING: ADMIN_PIN is not set. Admin actions will fail until set.");

const AUTH_PIN = process.env.AUTH_PIN || "";
if (!AUTH_PIN) console.warn("WARNING: AUTH_PIN is not set. /api/auth will always deny.");

const UNBAN_PIN = process.env.UNBAN_PIN || "";
if (!UNBAN_PIN) console.warn("WARNING: UNBAN_PIN is not set. /api/unban will always deny.");

// Persist on disk if available
const DATA_DIR = process.env.DATA_DIR || process.cwd();
const STATE_FILE = path.join(DATA_DIR, "state.json");
const ACCESS_FILE = path.join(DATA_DIR, "access.json");

function nowMs() {
  return Date.now();
}

function makeId() {
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

function safeJsonParse(raw, fallback) {
  try { return JSON.parse(raw); } catch (e) { return fallback; }
}

// ---- State (broadcast + site-lockdown used by /api/state)
const state = {
  lockdown: { enabled: false, updatedAt: 0 },
  broadcast: null
};

function loadState() {
  try {
    const fs = require("fs");
    if (!fs.existsSync(STATE_FILE)) return;
    const raw = fs.readFileSync(STATE_FILE, "utf8");
    const parsed = safeJsonParse(raw, null);
    if (parsed && typeof parsed === "object") {
      if (parsed.lockdown && typeof parsed.lockdown.enabled === "boolean") {
        state.lockdown.enabled = parsed.lockdown.enabled;
        state.lockdown.updatedAt = Number(parsed.lockdown.updatedAt || 0);
      }
      if (parsed.broadcast && typeof parsed.broadcast === "object") state.broadcast = parsed.broadcast;
    }
  } catch (e) {
    console.warn("Failed to load state:", e);
  }
}

function saveState() {
  try {
    const fs = require("fs");
    fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2), "utf8");
  } catch (e) {
    console.warn("Failed to save state:", e);
  }
}

function pruneExpiredBroadcast() {
  if (!state.broadcast) return;
  if (typeof state.broadcast.expiresAt !== "number") return;
  if (nowMs() >= state.broadcast.expiresAt) {
    state.broadcast = null;
    saveState();
  }
}

// ---- Access Control Store (clientID bans + access-lockdown)
const accessStore = {
  lockdown: false, // access-lockdown (NOT the same as state.lockdown)
  clients: {}
};

function loadAccess() {
  try {
    const fs = require("fs");
    if (!fs.existsSync(ACCESS_FILE)) return;
    const raw = fs.readFileSync(ACCESS_FILE, "utf8");
    const parsed = safeJsonParse(raw, null);
    if (!parsed || typeof parsed !== "object") return;

    if (typeof parsed.lockdown === "boolean") accessStore.lockdown = parsed.lockdown;
    if (parsed.clients && typeof parsed.clients === "object") accessStore.clients = parsed.clients;
  } catch (e) {
    console.warn("Failed to load access store:", e);
  }
}

function saveAccess() {
  try {
    const fs = require("fs");
    fs.writeFileSync(ACCESS_FILE, JSON.stringify(accessStore, null, 2), "utf8");
  } catch (e) {
    console.warn("Failed to save access store:", e);
  }
}

function normalizeStr(x) {
  return (typeof x === "string") ? x.trim() : "";
}

function ensureClientRecord(clientID) {
  const id = normalizeStr(clientID);
  if (!id) return null;

  const existing = accessStore.clients[id];
  if (existing && typeof existing === "object") {
    existing.lastSeenAt = nowMs();
    return existing;
  }

  const rec = { status: "unbanned", firstSeenAt: nowMs(), lastSeenAt: nowMs() };
  accessStore.clients[id] = rec;
  saveAccess();
  return rec;
}

function computeAccessDecision(clientID) {
  const id = normalizeStr(clientID);
  if (!id) {
    if (accessStore.lockdown) return { banned: true, allowed: false, reason: "missing_client_id" };
    return { banned: false, allowed: true, reason: "missing_client_id_allowed" };
  }

  const rec = accessStore.clients[id];
  const isKnown = !!rec;

  if (isKnown && rec && rec.status === "banned") return { banned: true, allowed: false, reason: "known_banned" };

  if (accessStore.lockdown) {
    if (!isKnown) return { banned: true, allowed: false, reason: "lockdown_unknown" };
    return { banned: false, allowed: true, reason: "lockdown_known_unbanned" };
  }

  return { banned: false, allowed: true, reason: isKnown ? "known_unbanned" : "unknown_allowed" };
}

// ---- Admin auth (ADMIN_PIN header)
function requirePin(req, res, next) {
  const pin = req.header("x-admin-pin") || "";
  if (!ADMIN_PIN || pin !== ADMIN_PIN) return res.status(401).json({ ok: false, error: "Unauthorized" });
  next();
}

// ---- CORS
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-Admin-Pin");
  if (req.method === "OPTIONS") return res.status(204).end();
  next();
});

// ---- Public endpoints
app.get("/health", (req, res) => {
  pruneExpiredBroadcast();
  res.json({ ok: true });
});

app.get("/api/state", (req, res) => {
  pruneExpiredBroadcast();
  res.json({ ok: true, lockdown: state.lockdown, broadcast: state.broadcast });
});

// ---- Server-side "Access Restricted" PIN validation
// POST /api/auth
// Body: { clientID, pinAttempt }
// Response: { ok: true, allowed: boolean }
app.post("/api/auth", (req, res) => {
  const clientID = normalizeStr(req.body && req.body.clientID);
  const pinAttempt = normalizeStr(req.body && req.body.pinAttempt);

  // Track as known (optional but useful)
  if (clientID) ensureClientRecord(clientID);

  if (!AUTH_PIN) return res.json({ ok: true, allowed: false });

  const allowed = pinAttempt === AUTH_PIN;

  // Optional: if they successfully authenticate, mark them unbanned so they become "known allowed" in access-lockdown mode.
  if (allowed && clientID) {
    const rec = ensureClientRecord(clientID);
    rec.status = "unbanned";
    rec.lastSeenAt = nowMs();
    saveAccess();
  }

  res.json({ ok: true, allowed });
});

// ---- ClientID access control endpoints
app.post("/api/check", (req, res) => {
  const clientID = normalizeStr(req.body && req.body.clientID);
  if (clientID) ensureClientRecord(clientID);

  const decision = computeAccessDecision(clientID);
  res.json({ ok: true, banned: !!decision.banned, allowed: !!decision.allowed, lockdown: !!accessStore.lockdown });
});

// POST /api/unban (banned page)
// Body: { clientID, pinAttempt }
// Response: { ok: true, allowed: boolean }
app.post("/api/unban", (req, res) => {
  const clientID = normalizeStr(req.body && req.body.clientID);
  const pinAttempt = normalizeStr(req.body && req.body.pinAttempt);

  if (!clientID) return res.status(400).json({ ok: false, error: "clientID required" });
  if (!UNBAN_PIN) return res.json({ ok: true, allowed: false });
  if (pinAttempt !== UNBAN_PIN) return res.json({ ok: true, allowed: false });

  const rec = ensureClientRecord(clientID);
  rec.status = "unbanned";
  rec.lastSeenAt = nowMs();
  saveAccess();

  res.json({ ok: true, allowed: true });
});

// ---- Admin endpoints for access control (ADMIN_PIN)
app.get("/api/admin/list", requirePin, (req, res) => {
  const items = Object.entries(accessStore.clients || {}).map(([clientID, rec]) => ({
    clientID,
    status: rec && rec.status ? rec.status : "unbanned",
    firstSeenAt: rec && rec.firstSeenAt ? rec.firstSeenAt : 0,
    lastSeenAt: rec && rec.lastSeenAt ? rec.lastSeenAt : 0
  }));
  items.sort((a, b) => (b.lastSeenAt || 0) - (a.lastSeenAt || 0));
  res.json({ ok: true, lockdown: !!accessStore.lockdown, clients: items });
});

app.post("/api/admin/ban", requirePin, (req, res) => {
  const clientID = normalizeStr(req.body && req.body.clientID);
  if (!clientID) return res.status(400).json({ ok: false, error: "clientID required" });

  const rec = ensureClientRecord(clientID);
  rec.status = "banned";
  rec.lastSeenAt = nowMs();
  saveAccess();

  res.json({ ok: true, status: rec.status });
});

app.post("/api/admin/unban", requirePin, (req, res) => {
  const clientID = normalizeStr(req.body && req.body.clientID);
  if (!clientID) return res.status(400).json({ ok: false, error: "clientID required" });

  const rec = ensureClientRecord(clientID);
  rec.status = "unbanned";
  rec.lastSeenAt = nowMs();
  saveAccess();

  res.json({ ok: true, status: rec.status });
});

app.post("/api/admin/lockdown", requirePin, (req, res) => {
  const enabled = !!(req.body && req.body.enabled);
  accessStore.lockdown = enabled;
  saveAccess();
  res.json({ ok: true, lockdown: !!accessStore.lockdown });
});

// ---- Broadcast + site-lockdown admin endpoints (ADMIN_PIN)
app.post("/api/broadcast", requirePin, (req, res) => {
  const msg = (req.body && typeof req.body.message === "string") ? req.body.message.trim() : "";
  if (!msg) return res.status(400).json({ ok: false, error: "message required" });

  const createdAt = nowMs();
  const expiresAt = createdAt + 24 * 60 * 60 * 1000;

  const b = { id: makeId(), message: msg, createdAt, expiresAt };

  state.broadcast = b;
  saveState();

  broadcastWS({ type: "broadcast", broadcast: b });

  res.json({ ok: true, broadcast: b });
});

app.post("/api/lockdown", requirePin, (req, res) => {
  state.lockdown.enabled = true;
  state.lockdown.updatedAt = nowMs();
  saveState();

  broadcastWS({ type: "lockdown", enabled: true, updatedAt: state.lockdown.updatedAt });

  res.json({ ok: true, lockdown: state.lockdown });
});

app.post("/api/clear-lockdown", requirePin, (req, res) => {
  state.lockdown.enabled = false;
  state.lockdown.updatedAt = nowMs();
  saveState();

  broadcastWS({ type: "lockdown", enabled: false, updatedAt: state.lockdown.updatedAt });

  res.json({ ok: true, lockdown: state.lockdown });
});

// ---- Static admin UI
app.use("/", express.static(path.join(__dirname, "public"), { extensions: ["html"] }));

// ---- Server + WebSocket
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: "/ws" });

function safeSend(ws, obj) {
  try { ws.send(JSON.stringify(obj)); } catch (e) {}
}

function broadcastWS(obj) {
  const msg = JSON.stringify(obj);
  for (const client of wss.clients) {
    if (client.readyState === 1) {
      try { client.send(msg); } catch (e) {}
    }
  }
}

wss.on("connection", (ws) => {
  pruneExpiredBroadcast();
  safeSend(ws, { type: "state", lockdown: state.lockdown, broadcast: state.broadcast });
  ws.on("message", () => {});
});

loadState();
pruneExpiredBroadcast();
loadAccess();

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Divine Admin Panel listening on :${PORT}`);
  console.log(`State file: ${STATE_FILE}`);
  console.log(`Access file: ${ACCESS_FILE}`);
});
