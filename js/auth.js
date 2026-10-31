// Picks the right account backend automatically:
//   - js/supabase-config.js has real keys  -> Supabase (works on Netlify, no
//     server to run — see supabase-setup.sql)
//   - otherwise                            -> the local Node server
//     (server/server.mjs), for development on localhost
//
// Both implementations expose the exact same functions below, so nothing else
// in the site (or the Minecraft mod's ApiConfig.VERIFY_URL) needs to know or
// care which one is active.
import { SUPABASE_URL, SUPABASE_ANON_KEY } from "./supabase-config.js";

const useSupabase = Boolean(SUPABASE_URL) && Boolean(SUPABASE_ANON_KEY);
const impl = useSupabase ? import("./auth-supabase.js") : import("./auth-local.js");
async function backend() { return impl; }

export const configured = true;

export async function signUp(email, password) { return (await backend()).signUp(email, password); }
export async function signIn(email, password) { return (await backend()).signIn(email, password); }
export async function signOut() { return (await backend()).signOut(); }
export async function getSession() { return (await backend()).getSession(); }
export async function getProfile() { return (await backend()).getProfile(); }
export async function setHwid(hwid) { return (await backend()).setHwid(hwid); }
export async function resetHwid() { return (await backend()).resetHwid(); }
export async function setLicenseKey(key) { return (await backend()).setLicenseKey(key); }
export async function getClientToken() { return (await backend()).getClientToken(); }
export async function regenerateClientToken() { return (await backend()).regenerateClientToken(); }

export async function isAdmin() { return (await backend()).isAdmin(); }
export async function adminListUsers() { return (await backend()).adminListUsers(); }
export async function adminSetTier(email, tier) { return (await backend()).adminSetTier(email, tier); }
export async function adminSetBlacklist(email, on) { return (await backend()).adminSetBlacklist(email, on); }
export async function adminSetWhitelist(email, on) { return (await backend()).adminSetWhitelist(email, on); }
export async function adminResetHwid(email) { return (await backend()).adminResetHwid(email); }
export async function adminMintKey(hwid, tier, days) { return (await backend()).adminMintKey(hwid, tier, days); }

export async function requireSession(loginUrl = "login.html") {
  const session = await getSession();
  if (!session) {
    window.location.replace(loginUrl);
    return null;
  }
  return session;
}
