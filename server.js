// Divine Admin Panel server
// - WebSocket for pushing events to connected clients on the Divine static site
// - HTTP API for admin actions (PIN-protected)
// - Public state endpoint for static clients to fetch on load
//
// ENV:
//   ADMIN_PIN=.... (required)

const path = require("path");
const express = require("express");
const http = require("http");
const { WebSocketServer } = require("ws");

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "256kb" }));

// ---- Config
const ADMIN_PIN = process.env.ADMIN_PIN || "";
if (!ADMIN_PIN) {
  console.warn("WARNING: ADMIN_PIN is not set. Admin actions will fail until set.");
}

// Persist on disk if available (you said you have persistent disk)
const DATA_DIR = process.env.DATA_DIR || process.cwd();
const STATE_FILE = path.join(DATA_DIR, "state.json");

function nowMs() {
  return Date.now();
}

function makeId() {
  // simple unique id
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

// ---- State
const state = {
  lockdown: {
    enabled: false,
    updatedAt: 0
  },
  broadcast: null
  // broadcast shape:
  // {
  //   id: string,
  //   message: string,
  //   createdAt: number,
  //   expiresAt: number
  // }
};

function loadState() {
  try {
    const fs = require("fs");
    if (!fs.existsSync(STATE_FILE)) return;
    const raw = fs.readFileSync(STATE_FILE, "utf8");
    const parsed = JSON.parse(raw);

    if (parsed && typeof parsed === "object") {
      if (parsed.lockdown && typeof parsed.lockdown.enabled === "boolean") {
        state.lockdown.enabled = parsed.lockdown.enabled;
        state.lockdown.updatedAt = Number(parsed.lockdown.updatedAt || 0);
      }
      if (parsed.broadcast && typeof parsed.broadcast === "object") {
        state.broadcast = parsed.broadcast;
      }
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

// ---- Admin auth
function requirePin(req, res, next) {
  const pin = req.header("x-admin-pin") || "";
  if (!ADMIN_PIN || pin !== ADMIN_PIN) {
    return res.status(401).json({ ok: false, error: "Unauthorized" });
  }
  next();
}

// ---- CORS (so your static Divine site can call dv-panel.giize.com)
app.use((req, res, next) => {
  // If you want to lock this down further, replace "*" with your Divine site origin.
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
  res.json({
    ok: true,
    lockdown: state.lockdown,
    broadcast: state.broadcast
  });
});

// ---- Admin endpoints (PIN required)
app.post("/api/broadcast", requirePin, (req, res) => {
  const msg = (req.body && typeof req.body.message === "string") ? req.body.message.trim() : "";
  if (!msg) return res.status(400).json({ ok: false, error: "message required" });

  const createdAt = nowMs();
  const expiresAt = createdAt + 24 * 60 * 60 * 1000;

  const b = {
    id: makeId(),
    message: msg,
    createdAt,
    expiresAt
  };

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
  } catch (e) {
    // ignore
  }
}

function broadcastWS(obj) {
  const msg = JSON.stringify(obj);
  for (const client of wss.clients) {
    if (client.readyState === 1) {
      try {
        client.send(msg);
      } catch (e) {
        // ignore
      }
    }
  }
}

wss.on("connection", (ws) => {
  // Send current state snapshot immediately
  pruneExpiredBroadcast();
  safeSend(ws, { type: "state", lockdown: state.lockdown, broadcast: state.broadcast });

  ws.on("message", () => {
    // Clients never need to send anything.
  });
});

loadState();
pruneExpiredBroadcast();

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Divine Admin Panel listening on :${PORT}`);
  console.log(`State file: ${STATE_FILE}`);
});
