// Data layer for AntiClient accounts. Talks to the local Node API (server/server.mjs).
import { API_BASE } from "./config.js";

// Always true for the local backend (the API is served from the same origin).
export const configured = true;

async function api(path, { method = "GET", body } = {}) {
  const res = await fetch(API_BASE + path, {
    method,
    headers: body ? { "content-type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
    credentials: "same-origin",
  });
  let data = {};
  try { data = await res.json(); } catch { /* no body */ }
  if (!res.ok) throw new Error(data.error || "Request failed.");
  return data;
}

export async function signUp(email, password) {
  await api("/api/register", { method: "POST", body: { email, password } });
  // No email confirmation step with the local backend.
  return { needsConfirmation: false };
}

export async function signIn(email, password) {
  await api("/api/login", { method: "POST", body: { email, password } });
}

export async function signOut() {
  await api("/api/logout", { method: "POST" });
}

// Returns a session-like object when signed in, or null.
export async function getSession() {
  try {
    const { profile } = await api("/api/me");
    return { user: { email: profile.email } };
  } catch {
    return null;
  }
}

export async function getProfile() {
  const { profile } = await api("/api/me");
  return profile;
}

export async function setLicenseKey(key) {
  await api("/api/license", { method: "POST", body: { key } });
}

// The "client token" is what the Minecraft mod itself presents (Account tab,
// pasted the same place as a license key) to prove which account it's running
// for — separate from your password so it's safe to keep in a config file.
export async function getClientToken() {
  const { token } = await api("/api/client-token");
  return token;
}

export async function regenerateClientToken() {
  const { token } = await api("/api/client-token/regenerate", { method: "POST" });
  return token;
}

// ---- admin -----------------------------------------------------------------
// Gated entirely server-side by ADMIN_EMAIL (server/server.mjs). Nothing
// client-side to configure.
export async function isAdmin() {
  try { return (await api("/api/admin/check")).isAdmin; } catch { return false; }
}

export async function adminListUsers() {
  return (await api("/api/admin/users")).users;
}

export async function adminSetTier(email, tier) {
  return (await api("/api/admin/set-tier", { method: "POST", body: { email, tier } })).profile;
}

export async function adminSetBlacklist(email, on) {
  return (await api("/api/admin/blacklist", { method: "POST", body: { email, on } })).profile;
}

export async function adminSetWhitelist(email, on) {
  return (await api("/api/admin/whitelist", { method: "POST", body: { email, on } })).profile;
}

export async function adminMintKey(hwid, tier, days) {
  return (await api("/api/admin/mint-key", { method: "POST", body: { hwid, tier, days } })).key;
}

export async function requireSession(loginUrl = "login.html") {
  const session = await getSession();
  if (!session) {
    window.location.replace(loginUrl);
    return null;
  }
  return session;
}
