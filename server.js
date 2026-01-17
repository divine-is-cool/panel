// Divine Admin Panel server
// - WebSocket for pushing events to connected clients on the Divine static site
// - HTTP API for admin actions (PIN-protected) (broadcast + site lockdown admin actions)
// - Public state endpoint for static clients to fetch on load
// - ClientID access control system (bans + access-lockdown + verification + suspicious)
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

// If you deploy behind a reverse proxy (Render/Railway/Cloudflare/etc.),
// set TRUST_PROXY=1 so req.ip becomes the real client IP.
if (String(process.env.TRUST_PROXY || "") === "1") {
  app.set("trust proxy", 1);
}

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
  try {
    return JSON.parse(raw);
  } catch (e) {
    return fallback;
  }
}

function normalizeStr(x) {
  return typeof x === "string" ? x.trim() : "";
}

function clampStr(s, maxLen) {
  const x = normalizeStr(s);
  if (!x) return "";
  if (x.length <= maxLen) return x;
  return x.slice(0, maxLen);
}

function getRequestIP(req) {
  // With trust proxy, req.ip is derived from x-forwarded-for properly.
  // Without trust proxy, it will be remoteAddress.
  return normalizeStr(req.ip || req.socket?.remoteAddress || "");
}

function formatUA(ua) {
  return clampStr(ua, 300);
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

// ---- Access Control Store (clientID bans + access-lockdown + status + ip bans)
const accessStore = {
  lockdown: false, // access-lockdown (NOT the same as state.lockdown)
  clients: {},
  ipBans: {} // { [ip]: { message, createdAt, updatedAt } }
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
    if (parsed.ipBans && typeof parsed.ipBans === "object") accessStore.ipBans = parsed.ipBans;
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

function normalizeLegacyStatus(status) {
  // Back-compat with your old values.
  // Old: "unbanned" meant allowed. New model: "unverified" default.
  const s = normalizeStr(status).toLowerCase();
  if (!s) return "unverified";
  if (s === "unbanned") return "unverified";
  if (s === "banned") return "banned";
  if (s === "verified") return "verified";
  if (s === "unverified") return "unverified";
  if (s === "suspicious") return "suspicious";
  return "unverified";
}

function ensureClientRecord(clientID) {
  const id = normalizeStr(clientID);
  if (!id) return null;

  const existing = accessStore.clients[id];
  if (existing && typeof existing === "object") {
    existing.lastSeenAt = nowMs();
    existing.status = normalizeLegacyStatus(existing.status);
    return existing;
  }

  const rec = {
    status: "unverified",
    firstSeenAt: nowMs(),
    lastSeenAt: nowMs(),
    verifiedAt: 0,
    suspiciousAt: 0,

    // telemetry
    ua: "",
    platform: "",
    language: "",
    timezone: "",
    screen: "",

    // ip tracking
    ipFirst: "",
    ipLast: "",
    ipLastSeenAt: 0,

    // ban message (client ban)
    banMessage: ""
  };

  accessStore.clients[id] = rec;
  saveAccess();
  return rec;
}

function recordClientTelemetry(req, clientID, device) {
  const rec = ensureClientRecord(clientID);
  if (!rec) return;

  const ip = getRequestIP(req);
  const ua = formatUA(req.headers["user-agent"] || "");

  if (!rec.ipFirst && ip) rec.ipFirst = ip;
  if (ip) {
    rec.ipLast = ip;
    rec.ipLastSeenAt = nowMs();
  }

  // Prefer explicit device payload if provided, else at least store UA.
  const d = device && typeof device === "object" ? device : {};
  rec.ua = formatUA(d.ua || ua);
  rec.platform = clampStr(d.platform || "", 80);
  rec.language = clampStr(d.language || "", 40);
  rec.timezone = clampStr(d.timezone || "", 64);
  rec.screen = clampStr(d.screen || "", 32);

  rec.lastSeenAt = nowMs();
  saveAccess();
}

function isDesktopish(rec) {
  // Very rough heuristic based on stored platform/ua. This is not security; it's just an ops heuristic.
  const ua = String(rec && rec.ua ? rec.ua : "").toLowerCase();
  const platform = String(rec && rec.platform ? rec.platform : "").toLowerCase();

  if (platform.includes("win")) return true;
  if (platform.includes("mac")) return true;
  if (ua.includes("windows")) return true;
  if (ua.includes("mac os")) return true;

  return false;
}

function ipBanDecision(ip) {
  const x = normalizeStr(ip);
  if (!x) return null;
  const rec = accessStore.ipBans && accessStore.ipBans[x];
  if (!rec || typeof rec !== "object") return null;
  return {
    banned: true,
    reason: "ip_ban",
    banMessage: clampStr(rec.message || "", 500)
  };
}

function computeAccessDecision(req, clientID) {
  const id = normalizeStr(clientID);
  const ip = getRequestIP(req);

  // IP ban takes precedence
  const ipBan = ipBanDecision(ip);
  if (ipBan) return { ...ipBan, allowed: false };

  if (!id) {
    if (accessStore.lockdown) return { banned: true, allowed: false, reason: "missing_client_id" };
    return { banned: false, allowed: true, reason: "missing_client_id_allowed" };
  }

  const rec = accessStore.clients[id];
  const isKnown = !!rec;

  if (isKnown && rec) rec.status = normalizeLegacyStatus(rec.status);

  if (isKnown && rec && rec.status === "banned") {
    return {
      banned: true,
      allowed: false,
      reason: "client_ban",
      status: "banned",
      banMessage: clampStr(rec.banMessage || "", 500)
    };
  }

  if (isKnown && rec && rec.status === "suspicious") {
    return { banned: false, allowed: true, reason: "client_suspicious", status: "suspicious" };
  }

  // Device targeting -> mark suspicious (server-side, not purely client)
  // Only applies if they're currently NOT verified/banned.
  if (isKnown && rec && rec.status === "unverified" && isDesktopish(rec)) {
    // Keep it sticky; once suspicious, stay until admin verifies/clears.
    rec.status = "suspicious";
    rec.suspiciousAt = nowMs();
    saveAccess();
    return { banned: false, allowed: true, reason: "desktop_unverified_marked_suspicious", status: "suspicious" };
  }

  if (accessStore.lockdown) {
    if (!isKnown) return { banned: true, allowed: false, reason: "lockdown_unknown" };

    // In lockdown mode, only allow verified (and optionally unverified if you want).
    // You asked for “manual authorize”, so deny unverified/suspicious when lockdown is ON.
    const st = normalizeLegacyStatus(rec.status);
    if (st !== "verified") return { banned: true, allowed: false, reason: "lockdown_not_verified", status: st };
    return { banned: false, allowed: true, reason: "lockdown_verified", status: st };
  }

  // Normal mode:
  // - unknown allowed
  // - known allowed unless banned; suspicious will be handled by client redirect to /suspicious
  return { banned: false, allowed: true, reason: isKnown ? "known_allowed" : "unknown_allowed", status: isKnown ? rec.status : "unverified" };
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

// ---- Telemetry / presence (static site calls this)
app.post("/api/hello", (req, res) => {
  const clientID = normalizeStr(req.body && req.body.clientID);
  const device = (req.body && typeof req.body.device === "object") ? req.body.device : null;

  if (!clientID) return res.status(400).json({ ok: false, error: "clientID required" });

  recordClientTelemetry(req, clientID, device);

  const rec = ensureClientRecord(clientID);
  res.json({
    ok: true,
    clientID,
    status: rec ? normalizeLegacyStatus(rec.status) : "unverified"
  });
});

// ---- Server-side "Access Restricted" PIN validation
// POST /api/auth
// Body: { clientID, pinAttempt }
// Response: { ok: true, allowed: boolean }
app.post("/api/auth", (req, res) => {
  const clientID = normalizeStr(req.body && req.body.clientID);
  const pinAttempt = normalizeStr(req.body && req.body.pinAttempt);

  if (clientID) recordClientTelemetry(req, clientID, null);

  if (!AUTH_PIN) return res.json({ ok: true, allowed: false });

  const allowed = pinAttempt === AUTH_PIN;

  if (allowed && clientID) {
    const rec = ensureClientRecord(clientID);
    if (rec) {
      rec.status = "verified";
      rec.verifiedAt = nowMs();
      rec.lastSeenAt = nowMs();
      saveAccess();
    }
  }

  res.json({ ok: true, allowed });
});

// ---- ClientID access control endpoints
app.post("/api/check", (req, res) => {
  const clientID = normalizeStr(req.body && req.body.clientID);
  if (clientID) recordClientTelemetry(req, clientID, null);

  const decision = computeAccessDecision(req, clientID);

  res.json({
    ok: true,
    banned: !!decision.banned,
    allowed: !!decision.allowed,
    lockdown: !!accessStore.lockdown,
    status: decision.status || "unverified",
    reason: decision.reason || "",
    banMessage: decision.banMessage || ""
  });
});

// POST /api/unban (banned page)
// Body: { clientID, pinAttempt }
// Response: { ok: true, allowed: boolean }
app.post("/api/unban", (req, res) => {
  const clientID = normalizeStr(req.body && req.body.clientID);
  const pinAttempt = normalizeStr(req.body && req.body.pinAttempt);

  if (!clientID) return res.status(400).json({ ok: false, error: "clientID required" });
  recordClientTelemetry(req, clientID, null);

  if (!UNBAN_PIN) return res.json({ ok: true, allowed: false });
  if (pinAttempt !== UNBAN_PIN) return res.json({ ok: true, allowed: false });

  const rec = ensureClientRecord(clientID);
  if (rec) {
    // Unban does NOT automatically verify; it just clears ban + suspicious.
    rec.status = "unverified";
    rec.banMessage = "";
    rec.lastSeenAt = nowMs();
    saveAccess();
  }

  res.json({ ok: true, allowed: true });
});

// ---- Admin endpoints for user management (ADMIN_PIN)

// List clients
app.get("/api/admin/list", requirePin, (req, res) => {
  const items = Object.entries(accessStore.clients || {}).map(([clientID, rec]) => {
    const r = rec && typeof rec === "object" ? rec : {};
    const status = normalizeLegacyStatus(r.status);
    return {
      clientID,
      status,
      firstSeenAt: Number(r.firstSeenAt || 0),
      lastSeenAt: Number(r.lastSeenAt || 0),
      verifiedAt: Number(r.verifiedAt || 0),
      suspiciousAt: Number(r.suspiciousAt || 0),

      ipFirst: normalizeStr(r.ipFirst || ""),
      ipLast: normalizeStr(r.ipLast || ""),
      ipLastSeenAt: Number(r.ipLastSeenAt || 0),

      ua: normalizeStr(r.ua || ""),
      platform: normalizeStr(r.platform || ""),
      language: normalizeStr(r.language || ""),
      timezone: normalizeStr(r.timezone || ""),
      screen: normalizeStr(r.screen || ""),

      banMessage: normalizeStr(r.banMessage || "")
    };
  });

  items.sort((a, b) => (b.lastSeenAt || 0) - (a.lastSeenAt || 0));
  res.json({
    ok: true,
    lockdown: !!accessStore.lockdown,
    clients: items,
    ipBans: accessStore.ipBans || {}
  });
});

// Verify user
app.post("/api/admin/verify", requirePin, (req, res) => {
  const clientID = normalizeStr(req.body && req.body.clientID);
  if (!clientID) return res.status(400).json({ ok: false, error: "clientID required" });

  const rec = ensureClientRecord(clientID);
  if (!rec) return res.status(400).json({ ok: false, error: "clientID required" });

  rec.status = "verified";
  rec.verifiedAt = nowMs();
  rec.lastSeenAt = nowMs();
  saveAccess();

  res.json({ ok: true, status: rec.status });
});

// Mark suspicious (optional admin control)
app.post("/api/admin/suspicious", requirePin, (req, res) => {
  const clientID = normalizeStr(req.body && req.body.clientID);
  if (!clientID) return res.status(400).json({ ok: false, error: "clientID required" });

  const rec = ensureClientRecord(clientID);
  if (!rec) return res.status(400).json({ ok: false, error: "clientID required" });

  rec.status = "suspicious";
  rec.suspiciousAt = nowMs();
  rec.lastSeenAt = nowMs();
  saveAccess();

  res.json({ ok: true, status: rec.status });
});

// Clear suspicious back to unverified
app.post("/api/admin/clear-suspicious", requirePin, (req, res) => {
  const clientID = normalizeStr(req.body && req.body.clientID);
  if (!clientID) return res.status(400).json({ ok: false, error: "clientID required" });

  const rec = ensureClientRecord(clientID);
  if (!rec) return res.status(400).json({ ok: false, error: "clientID required" });

  if (normalizeLegacyStatus(rec.status) === "suspicious") {
    rec.status = "unverified";
    rec.lastSeenAt = nowMs();
    saveAccess();
  }

  res.json({ ok: true, status: normalizeLegacyStatus(rec.status) });
});

// Ban clientID (with message)
app.post("/api/admin/ban", requirePin, (req, res) => {
  const clientID = normalizeStr(req.body && req.body.clientID);
  const banMessage = clampStr(req.body && req.body.banMessage, 500);
  if (!clientID) return res.status(400).json({ ok: false, error: "clientID required" });

  const rec = ensureClientRecord(clientID);
  rec.status = "banned";
  rec.banMessage = banMessage;
  rec.lastSeenAt = nowMs();
  saveAccess();

  res.json({ ok: true, status: rec.status });
});

// Unban clientID
app.post("/api/admin/unban", requirePin, (req, res) => {
  const clientID = normalizeStr(req.body && req.body.clientID);
  if (!clientID) return res.status(400).json({ ok: false, error: "clientID required" });

  const rec = ensureClientRecord(clientID);
  rec.status = "unverified";
  rec.banMessage = "";
  rec.lastSeenAt = nowMs();
  saveAccess();

  res.json({ ok: true, status: rec.status });
});

// Ban IP (with message)
app.post("/api/admin/ban-ip", requirePin, (req, res) => {
  const ip = normalizeStr(req.body && req.body.ip);
  const banMessage = clampStr(req.body && req.body.banMessage, 500);
  if (!ip) return res.status(400).json({ ok: false, error: "ip required" });

  const existing = accessStore.ipBans[ip];
  const createdAt = existing && existing.createdAt ? Number(existing.createdAt) : nowMs();

  accessStore.ipBans[ip] = {
    message: banMessage,
    createdAt,
    updatedAt: nowMs()
  };
  saveAccess();

  res.json({ ok: true, ip, banned: true });
});

// Unban IP
app.post("/api/admin/unban-ip", requirePin, (req, res) => {
  const ip = normalizeStr(req.body && req.body.ip);
  if (!ip) return res.status(400).json({ ok: false, error: "ip required" });

  if (accessStore.ipBans && accessStore.ipBans[ip]) {
    delete accessStore.ipBans[ip];
    saveAccess();
  }

  res.json({ ok: true, ip, banned: false });
});

// Access lockdown toggle
app.post("/api/admin/lockdown", requirePin, (req, res) => {
  const enabled = !!(req.body && req.body.enabled);
  accessStore.lockdown = enabled;
  saveAccess();
  res.json({ ok: true, lockdown: !!accessStore.lockdown });
});

// ---- Broadcast + site-lockdown admin endpoints (ADMIN_PIN)
app.post("/api/broadcast", requirePin, (req, res) => {
  const msg = req.body && typeof req.body.message === "string" ? req.body.message.trim() : "";
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
  try {
    ws.send(JSON.stringify(obj));
  } catch (e) {}
}

function broadcastWS(obj) {
  const msg = JSON.stringify(obj);
  for (const client of wss.clients) {
    if (client.readyState === 1) {
      try {
        client.send(msg);
      } catch (e) {}
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
