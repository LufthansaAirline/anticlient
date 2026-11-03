-- =============================================================================
-- AntiClient accounts — database setup (Netlify-ready, hosted on Supabase)
-- Run this once in your Supabase project: SQL Editor -> New query -> paste -> Run.
--
-- This gives the static site (login.html / dashboard.html) real accounts, and
-- gives the Minecraft mod itself a way to verify a "client token" online —
-- see client_verify() below, which net.anticlient.client.service.LicenseAccount
-- calls (ApiConfig.VERIFY_URL) when someone pastes a token into the Account tab.
-- =============================================================================

create extension if not exists pgcrypto;

-- 1. Profile table (one row per user, created automatically on sign-up)
--    hwid is informational only ("last seen from") — not used to grant or
--    deny access. Keys and tokens work from any PC.
create table if not exists public.profiles (
  id            uuid primary key references auth.users (id) on delete cascade,
  email         text,
  tier          text not null default 'free',
  license_key   text,
  hwid          text,
  client_token  text not null default ('tok_' || encode(gen_random_bytes(24), 'hex')),
  created_at    timestamptz not null default now()
);
create unique index if not exists profiles_client_token_key on public.profiles (client_token);

-- 2. Create a profile row whenever a new auth user appears
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
begin
  insert into public.profiles (id, email) values (new.id, new.email)
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- 3. Row Level Security: signed-in users may only READ their own row (including
--    their own client_token). All writes go through the SECURITY DEFINER
--    functions below, and client_verify() can look up ANY user by token
--    without needing that user's session (the mod isn't logged in as a
--    Supabase user).
alter table public.profiles enable row level security;

drop policy if exists "read own profile" on public.profiles;
create policy "read own profile" on public.profiles
  for select using (auth.uid() = id);

-- 4. Save a license key on the account (the offline, signed ANTI-... keys).
create or replace function public.set_license_key(new_key text)
returns void
language plpgsql
security definer set search_path = public
as $$
begin
  if new_key !~ '^ANTI-' then
    raise exception 'That does not look like a key (should start with ANTI-)';
  end if;
  update public.profiles set license_key = new_key where id = auth.uid();
end;
$$;

-- 5. Regenerate the client token (invalidates the old one immediately).
create or replace function public.regenerate_client_token()
returns text
language plpgsql
security definer set search_path = public
as $$
declare new_token text := 'tok_' || encode(gen_random_bytes(24), 'hex');
begin
  update public.profiles set client_token = new_token where id = auth.uid();
  return new_token;
end;
$$;

-- 6. Called directly by the Minecraft client — NOT by a logged-in browser.
--    The token itself is the credential, so this runs for the "anon" role with
--    no user session. Not PC-locked: works from any HWID. The reported HWID
--    is recorded only as "last seen from" info, matching server/server.mjs.
create or replace function public.client_verify(token text, hwid text)
returns jsonb
language plpgsql
security definer set search_path = public
as $$
declare
  row_id uuid;
  row_tier text;
  hwid_up text := upper(coalesce(hwid, ''));
begin
  select id, tier into row_id, row_tier
    from public.profiles where client_token = token;

  if row_id is null then
    return jsonb_build_object('ok', false, 'tier', 'FREE', 'error', 'That token isn''t valid.');
  end if;

  if hwid_up ~ '^[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$' then
    update public.profiles set hwid = hwid_up where id = row_id;
  end if;

  return jsonb_build_object('ok', true, 'tier', upper(row_tier), 'error', null);
end;
$$;

-- 7. Grants. client_verify is callable by the public "anon" key (the mod has
--    no Supabase login) — everything else needs a signed-in user.
grant execute on function public.set_license_key(text)       to authenticated;
grant execute on function public.regenerate_client_token()   to authenticated;
grant execute on function public.client_verify(text, text)   to anon, authenticated;

-- Backfill profiles for any users that already existed before this ran.
insert into public.profiles (id, email)
  select id, email from auth.users
  on conflict (id) do nothing;
