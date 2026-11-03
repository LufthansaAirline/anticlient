// Data layer for AntiClient accounts — Supabase-backed (works on Netlify static
// hosting; no server to run). Used automatically once js/supabase-config.js has
// real keys in it; see js/auth.js.
import { createClient } from "https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2.45.4/+esm";
import { SUPABASE_URL, SUPABASE_ANON_KEY } from "./supabase-config.js";

export const configured = true;

const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

export async function signUp(email, password) {
  const { data, error } = await supabase.auth.signUp({ email, password });
  if (error) throw error;
  // When email confirmation is on, data.session is null until they confirm.
  return { needsConfirmation: !data.session };
}

export async function signIn(email, password) {
  const { error } = await supabase.auth.signInWithPassword({ email, password });
  if (error) throw error;
}

export async function signOut() {
  await supabase.auth.signOut();
}

export async function getSession() {
  const { data } = await supabase.auth.getSession();
  return data.session;
}

export async function getProfile() {
  const { data, error } = await supabase
    .from("profiles")
    .select("email, tier, license_key, hwid")
    .single();
  if (error) throw error;
  return data;
}

export async function setLicenseKey(key) {
  const { error } = await supabase.rpc("set_license_key", { new_key: key });
  if (error) throw error;
}

export async function getClientToken() {
  const { data, error } = await supabase.from("profiles").select("client_token").single();
  if (error) throw error;
  return data.client_token;
}

export async function regenerateClientToken() {
  const { data, error } = await supabase.rpc("regenerate_client_token");
  if (error) throw error;
  return data;
}

// Admin tools (key minting especially, which needs Ed25519 signing) aren't
// implemented for the Supabase backend yet — only the local Node server.
function adminUnsupported() {
  throw new Error("Admin tools need the local server (server/server.mjs), not yet available on Supabase.");
}
export async function isAdmin() { return false; }
export async function adminListUsers() { return adminUnsupported(); }
export async function adminSetTier() { return adminUnsupported(); }
export async function adminSetBlacklist() { return adminUnsupported(); }
export async function adminSetWhitelist() { return adminUnsupported(); }
export async function adminMintKey() { return adminUnsupported(); }

export async function requireSession(loginUrl = "login.html") {
  const session = await getSession();
  if (!session) {
    window.location.replace(loginUrl);
    return null;
  }
  return session;
}
