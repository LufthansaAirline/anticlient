// AntiClient accounts — self-contained Node backend (no external dependencies).
// Serves the static site AND a small JSON API with real auth:
//   - passwords hashed with scrypt + per-user salt
//   - sessions as HMAC-signed, httpOnly cookies
//   - users persisted to server/data.json
//   - a per-account "client token" the Minecraft mod itself can verify against
//     (see /api/client/verify — this is what net.anticlient.client.service
//     .LicenseAccount's online sign-in path calls)
//
// No PC-locking: keys and tokens work from any machine. The HWID the client
// reports on verify is kept only as an informational "last seen from" field
// (shown to the admin), never used to grant or deny access.
//
// Run:  node server/server.mjs   (from the anticlientwebsite folder)
//
// NOTE: this server keeps its data in a JSON file and in-process memory, so it
// needs to stay running somewhere — it will NOT work dropped onto Netlify
// as-is (Netlify only serves static files + short-lived stateless functions).
// It's designed to run standalone (e.g. Render, Railway, Fly, a VPS) with
// gogglesmp.com's DNS pointed at it directly — see supabase-setup.sql for an
// alternative if you'd rather keep the static site on Netlify instead.
//
// Config via env vars (all optional):
//   PORT                  - what to listen on (hosts like Render set this)
//   DATA_DIR              - where data.json/secret.key live; point this at a
//                            persistent disk in production, or they reset on
//                            every redeploy
//   ANTI_SIGNING_KEY_PEM  - the signing_key.pem's contents, for minting
//                            offline keys from a deployment that has no local
//                            file for it. Leave unset to disable remote
//                            minting (the admin "Accounts" tools still work
//                            fine without it) — putting your private signing
//                            key on a public server is a real decision, not
//                            a default.

import http from "http";
import { readFile } from "fs/promises";
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "fs";
import { randomBytes, scryptSync, timingSafeEqual, createHmac, createPrivateKey, sign as cryptoSign } from "crypto";
import { fileURLToPath } from "url";
import { dirname, join, normalize, extname } from "path";
import { homedir } from "os";

const __dirname = dirname(fileURLToPath(import.meta.url));
const SITE_ROOT = join(__dirname, "..");
const DATA_DIR = process.env.DATA_DIR ? process.env.DATA_DIR : __dirname;
const DATA_FILE = join(DATA_DIR, "data.json");
const SECRET_FILE = join(DATA_DIR, "secret.key");
const PORT = process.env.PORT || 8891;

const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const HWID_RE = /^[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}$/;

// Whoever's account has this email gets admin powers (mint offline keys,
// blacklist/whitelist accounts).
const ADMIN_EMAIL = "theshlerper@gmail.com";
function isAdmin(u) { return !!u && u.email === ADMIN_EMAIL; }

// ---- persistence ------------------------------------------------------------
if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });
let db = existsSync(DATA_FILE)
  ? JSON.parse(readFileSync(DATA_FILE, "utf8"))
  : { users: {}, byEmail: {} };
if (!db.byToken) db.byToken = {};
// Backfill an index + any fields added after some users were already saved.
let needsSave = false;
for (const u of Object.values(db.users)) {
  if (!u.client_token) { u.client_token = newToken(); needsSave = true; }
  if (u.blacklisted === undefined) { u.blacklisted = false; needsSave = true; }
  if (u.whitelisted === undefined) { u.whitelisted = false; needsSave = true; }
  db.byToken[u.client_token] = u.id;
}
function save() { writeFileSync(DATA_FILE, JSON.stringify(db, null, 2)); }
if (needsSave) save();

function newToken() { return "tok_" + randomBytes(24).toString("hex"); }

// ---- offline ANTI-... key minting (mirrors KeyMint.java / LicenseAccount.java) ---
// Looks in the same places the in-game dev Key Maker does, so admins who
// already have a signing_key.pem set up don't need to do anything extra.
function signingKeyCandidates() {
  const out = [];
  if (process.env.ANTI_KEY_PATH) out.push(process.env.ANTI_KEY_PATH);
  if (process.env.APPDATA) out.push(join(process.env.APPDATA, ".minecraft", "config", "anticlient", "signing_key.pem"));
  out.push(join(homedir(), "Desktop", "anticlient_signing_key.pem"));
  return out;
}

let signingKeyCache; // undefined = not tried yet, null = tried and missing
function loadSigningKey() {
  if (signingKeyCache !== undefined) return signingKeyCache;
  if (process.env.ANTI_SIGNING_KEY_PEM) {
    try {
      signingKeyCache = createPrivateKey({ key: process.env.ANTI_SIGNING_KEY_PEM, format: "pem", type: "pkcs8" });
      return signingKeyCache;
    } catch { /* malformed — fall through to file candidates */ }
  }
  for (const p of signingKeyCandidates()) {
    if (existsSync(p)) {
      try {
        signingKeyCache = createPrivateKey({ key: readFileSync(p, "utf8"), format: "pem", type: "pkcs8" });
        return signingKeyCache;
      } catch { /* malformed — try the next candidate */ }
    }
  }
  signingKeyCache = null;
  return null;
}

function parseHwidHex(text) {
  const hex = String(text || "").replace(/[\s-]/g, "");
  return /^[0-9a-fA-F]{16}$/.test(hex) ? Buffer.from(hex, "hex") : null;
}

// Builds the exact 16-byte payload + 64-byte Ed25519 signature LicenseAccount.java
// verifies: [0]=version(3) [1]=tierCode [2]=lifetime-flag [3]=reserved
// [4..7]=expiry unix-seconds big-endian (0=none) [8..15]=hwid bytes.
function mintOfflineKey(hwidBuf, tier, days) {
  const priv = loadSigningKey();
  if (!priv) {
    throw new Error(
      "No signing key found on this server. Put signing_key.pem at " + signingKeyCandidates()[1] + " (same one the game uses)."
    );
  }

  const payload = randomBytes(16); // random-fill first; only specific bytes are meaningful
  payload[0] = 3;
  payload[1] = tier === "PRO" ? 1 : 0;
  payload[2] = days === 0 ? 1 : 0; // lifetime
  payload[3] = 0;
  const expiresAt = days > 0 ? Math.floor(Date.now() / 1000) + days * 86400 : 0;
  payload.writeUInt32BE(expiresAt >>> 0, 4);
  hwidBuf.copy(payload, 8);

  const signature = cryptoSign(null, payload, priv); // Ed25519: algorithm must be null
  return "ANTI-" + Buffer.concat([payload, signature]).toString("base64url");
}

const SECRET = existsSync(SECRET_FILE)
  ? readFileSync(SECRET_FILE)
  : (() => { const s = randomBytes(32); writeFileSync(SECRET_FILE, s); return s; })();

// ---- helpers ----------------------------------------------------------------
const b64url = (buf) => Buffer.from(buf).toString("base64url");

function hashPassword(password, salt = randomBytes(16).toString("hex")) {
  const hash = scryptSync(password, salt, 64).toString("hex");
  return { salt, hash };
}
function verifyPassword(password, salt, hash) {
  const test = scryptSync(password, salt, 64).toString("hex");
  const a = Buffer.from(test), b = Buffer.from(hash);
  return a.length === b.length && timingSafeEqual(a, b);
}

function makeToken(uid) {
  const body = b64url(JSON.stringify({ uid, exp: Date.now() + SESSION_TTL_MS }));
  const sig = createHmac("sha256", SECRET).update(body).digest("base64url");
  return body + "." + sig;
}
function readToken(token) {
  if (!token || !token.includes(".")) return null;
  const [body, sig] = token.split(".");
  const expected = createHmac("sha256", SECRET).update(body).digest("base64url");
  const a = Buffer.from(sig), b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  try {
    const data = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    if (!data.exp || data.exp < Date.now()) return null;
    return data.uid;
  } catch { return null; }
}

function parseCookies(req) {
  const out = {};
  (req.headers.cookie || "").split(";").forEach((c) => {
    const i = c.indexOf("=");
    if (i > -1) out[c.slice(0, i).trim()] = decodeURIComponent(c.slice(i + 1).trim());
  });
  return out;
}
function currentUser(req) {
  const uid = readToken(parseCookies(req).ac_session);
  return uid && db.users[uid] ? db.users[uid] : null;
}
function publicProfile(u) {
  return { email: u.email, tier: u.tier, license_key: u.license_key || null, hwid: u.hwid || null };
}

function send(res, status, obj, headers = {}) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { "content-type": "application/json", ...headers });
  res.end(body);
}
function sessionCookie(token) {
  const parts = [`ac_session=${token}`, "Path=/", "HttpOnly", "SameSite=Lax", `Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`];
  return parts.join("; ");
}
function clearCookie() { return "ac_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"; }

function readJson(req) {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (c) => { data += c; if (data.length > 1e6) req.destroy(); });
    req.on("end", () => { try { resolve(JSON.parse(data || "{}")); } catch { resolve({}); } });
  });
}

// ---- API --------------------------------------------------------------------
async function handleApi(req, res, path) {
  if (req.method === "POST" && path === "/api/register") {
    const { email, password } = await readJson(req);
    const em = String(email || "").trim().toLowerCase();
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(em)) return send(res, 400, { error: "Enter a valid email." });
    if (String(password || "").length < 6) return send(res, 400, { error: "Password must be at least 6 characters." });
    if (db.byEmail[em]) return send(res, 409, { error: "An account with that email already exists." });
    const id = randomBytes(12).toString("hex");
    const { salt, hash } = hashPassword(password);
    const token = newToken();
    db.users[id] = {
      id, email: em, salt, hash, tier: "free", license_key: null, hwid: null,
      client_token: token, blacklisted: false, whitelisted: false, created_at: Date.now()
    };
    db.byEmail[em] = id;
    db.byToken[token] = id;
    save();
    return send(res, 200, { profile: publicProfile(db.users[id]) }, { "Set-Cookie": sessionCookie(makeToken(id)) });
  }

  if (req.method === "POST" && path === "/api/login") {
    const { email, password } = await readJson(req);
    const em = String(email || "").trim().toLowerCase();
    const id = db.byEmail[em];
    const u = id && db.users[id];
    if (!u || !verifyPassword(String(password || ""), u.salt, u.hash)) {
      return send(res, 401, { error: "Wrong email or password." });
    }
    return send(res, 200, { profile: publicProfile(u) }, { "Set-Cookie": sessionCookie(makeToken(id)) });
  }

  if (req.method === "POST" && path === "/api/logout") {
    return send(res, 200, { ok: true }, { "Set-Cookie": clearCookie() });
  }

  if (req.method === "GET" && path === "/api/me") {
    const u = currentUser(req);
    if (!u) return send(res, 401, { error: "Not signed in." });
    return send(res, 200, { profile: publicProfile(u) });
  }

  if (req.method === "POST" && path === "/api/license") {
    const u = currentUser(req);
    if (!u) return send(res, 401, { error: "Not signed in." });
    const { key } = await readJson(req);
    const k = String(key || "").trim();
    if (!/^ANTI-/i.test(k)) return send(res, 400, { error: "That doesn't look like a key (starts with ANTI-)." });
    u.license_key = k; save();
    return send(res, 200, { profile: publicProfile(u) });
  }

  // The dashboard's "Client token" panel — a secret, separate from the account
  // password, that the mod itself presents to /api/client/verify.
  if (req.method === "GET" && path === "/api/client-token") {
    const u = currentUser(req);
    if (!u) return send(res, 401, { error: "Not signed in." });
    return send(res, 200, { token: u.client_token });
  }

  if (req.method === "POST" && path === "/api/client-token/regenerate") {
    const u = currentUser(req);
    if (!u) return send(res, 401, { error: "Not signed in." });
    delete db.byToken[u.client_token];
    u.client_token = newToken();
    db.byToken[u.client_token] = u.id;
    save();
    return send(res, 200, { token: u.client_token });
  }

  // Called directly by the Minecraft client (no login cookie — the token IS the
  // credential). Works from any PC; the reported HWID is recorded for the
  // admin's info only, never checked against anything.
  if (req.method === "POST" && path === "/api/client/verify") {
    const { token, hwid } = await readJson(req);
    const t = String(token || "").trim();
    const h = String(hwid || "").trim().toUpperCase();
    const id = db.byToken[t];
    const u = id && db.users[id];
    if (!u) return send(res, 200, { ok: false, tier: "FREE", error: "That token isn't valid." });

    if (!isAdmin(u)) {
      if (u.blacklisted) {
        return send(res, 200, { ok: false, tier: "FREE", error: "This account has been blacklisted." });
      }
      const inviteOnly = Object.values(db.users).some((x) => x.whitelisted);
      if (inviteOnly && !u.whitelisted) {
        return send(res, 200, { ok: false, tier: "FREE", error: "Access is invite-only right now and this account isn't on the list." });
      }
    }

    if (HWID_RE.test(h) && u.hwid !== h) { u.hwid = h; save(); }
    return send(res, 200, { ok: true, tier: u.tier.toUpperCase(), error: null });
  }

  // ---- admin --------------------------------------------------------------
  // Gated entirely by ADMIN_EMAIL: only that account can reach any of these.
  function requireAdmin() {
    const u = currentUser(req);
    if (!u) { send(res, 401, { error: "Not signed in." }); return null; }
    if (!isAdmin(u)) { send(res, 403, { error: "Admin only." }); return null; }
    return u;
  }
  function adminProfile(u) {
    return {
      email: u.email, tier: u.tier, hwid: u.hwid || null,
      blacklisted: !!u.blacklisted, whitelisted: !!u.whitelisted, created_at: u.created_at
    };
  }
  function findByEmail(email) {
    const em = String(email || "").trim().toLowerCase();
    const id = db.byEmail[em];
    return id ? db.users[id] : null;
  }

  if (req.method === "GET" && path === "/api/admin/check") {
    return send(res, 200, { isAdmin: isAdmin(currentUser(req)) });
  }

  if (req.method === "GET" && path === "/api/admin/users") {
    if (!requireAdmin()) return;
    const list = Object.values(db.users).map(adminProfile).sort((a, b) => a.email.localeCompare(b.email));
    return send(res, 200, { users: list });
  }

  if (req.method === "POST" && path === "/api/admin/set-tier") {
    if (!requireAdmin()) return;
    const { email, tier } = await readJson(req);
    const u = findByEmail(email);
    if (!u) return send(res, 404, { error: "No account with that email." });
    const t = String(tier || "").toLowerCase();
    if (t !== "free" && t !== "pro") return send(res, 400, { error: "Tier must be free or pro." });
    u.tier = t; save();
    return send(res, 200, { profile: adminProfile(u) });
  }

  if (req.method === "POST" && path === "/api/admin/blacklist") {
    if (!requireAdmin()) return;
    const { email, on } = await readJson(req);
    const u = findByEmail(email);
    if (!u) return send(res, 404, { error: "No account with that email." });
    if (u.email === ADMIN_EMAIL) return send(res, 400, { error: "Can't blacklist the admin account." });
    u.blacklisted = !!on; save();
    return send(res, 200, { profile: adminProfile(u) });
  }

  if (req.method === "POST" && path === "/api/admin/whitelist") {
    if (!requireAdmin()) return;
    const { email, on } = await readJson(req);
    const u = findByEmail(email);
    if (!u) return send(res, 404, { error: "No account with that email." });
    u.whitelisted = !!on; save();
    return send(res, 200, { profile: adminProfile(u) });
  }

  if (req.method === "POST" && path === "/api/admin/mint-key") {
    if (!requireAdmin()) return;
    const { hwid, tier, days } = await readJson(req);
    // HWID is optional now — keys aren't PC-locked. Zero-fill if nothing usable was given.
    const hwidBuf = parseHwidHex(hwid) || Buffer.alloc(8);
    const t = String(tier || "FREE").toUpperCase();
    if (t !== "FREE" && t !== "PRO") return send(res, 400, { error: "Tier must be FREE or PRO." });
    const d = Number.isFinite(Number(days)) ? Math.max(0, Math.trunc(Number(days))) : 0;
    try {
      return send(res, 200, { key: mintOfflineKey(hwidBuf, t, d) });
    } catch (e) {
      return send(res, 500, { error: e.message || "Could not mint a key." });
    }
  }

  return send(res, 404, { error: "Unknown endpoint." });
}

// ---- static files -----------------------------------------------------------
const TYPES = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".png": "image/png", ".json": "application/json", ".jar": "application/java-archive", ".ico": "image/x-icon" };
async function handleStatic(req, res, path) {
  let p = path === "/" ? "/index.html" : path;
  const full = normalize(join(SITE_ROOT, p));
  if (!full.startsWith(normalize(SITE_ROOT))) { res.writeHead(403); return res.end("forbidden"); }
  try {
    const data = await readFile(full);
    res.writeHead(200, { "content-type": TYPES[extname(full)] || "application/octet-stream" });
    res.end(data);
  } catch {
    res.writeHead(404, { "content-type": "text/plain" });
    res.end("404");
  }
}

http.createServer(async (req, res) => {
  const path = decodeURIComponent(req.url.split("?")[0]);
  try {
    if (path.startsWith("/api/")) return await handleApi(req, res, path);
    return await handleStatic(req, res, path);
  } catch (e) {
    send(res, 500, { error: "Server error." });
  }
}).listen(PORT, () => console.log(`AntiClient site + API on http://localhost:${PORT}`));
