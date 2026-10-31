// ---------------------------------------------------------------------------
// Supabase connection details — fill these in to deploy on Netlify (or any
// static host). Leave them as-is to keep using the local Node server
// (server/server.mjs) for development; js/auth.js picks whichever is set up.
//
// 1. Create a free project at https://supabase.com
// 2. SQL Editor -> paste supabase-setup.sql -> Run
// 3. Project Settings -> API -> copy the "Project URL" and the "anon public" key
// 4. Paste them below and redeploy the site
//
// The anon key is SAFE to expose in the browser (and inside the Minecraft mod
// jar — see src/main/java/.../service/ApiConfig.java): it only allows what
// the Row Level Security policies / grants in supabase-setup.sql allow.
// Never put the "service_role" key here or anywhere client-side.
// ---------------------------------------------------------------------------

export const SUPABASE_URL = "";
export const SUPABASE_ANON_KEY = "";
