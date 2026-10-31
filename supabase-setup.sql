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
create table if not exists public.profiles (
  id            uuid primary key references auth.users (id) on delete cascade,
  email         text,
  tier          text not null default 'free',
  license_key   text,
  hwid          text,
  hwid_reset_at timestamptz,
  client_token  text not null default ('tok_' || encode(gen_random_bytes(24), 'hex')),
  created_at    timestamptz not null default now()
);
create unique index if not exists profiles_client_token_key on public.profiles (client_token);

-- Log of HWID resets (handy for support / abuse checks)
create table if not exists public.hwid_resets (
  id      bigint generated always as identity primary key,
  user_id uuid not null references auth.users (id) on delete cascade,
  at      timestamptz not null default now()
);

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
--    functions below, so the cooldown / format checks can't be bypassed from
--    the browser, and client_verify() can look up ANY user by token without
--    needing that user's session (the mod isn't logged in as a Supabase user).
alter table public.profiles    enable row level security;
alter table public.hwid_resets enable row level security;

drop policy if exists "read own profile" on public.profiles;
create policy "read own profile" on public.profiles
  for select using (auth.uid() = id);

drop policy if exists "read own resets" on public.hwid_resets;
create policy "read own resets" on public.hwid_resets
  for select using (auth.uid() = user_id);

-- 4. Bind a hardware ID (only allowed while none is set).
create or replace function public.set_hwid(new_hwid text)
returns void
language plpgsql
security definer set search_path = public
as $$
declare current_hwid text;
begin
  if new_hwid !~ '^[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}$' then
    raise exception 'HWID must look like XXXX-XXXX-XXXX-XXXX';
  end if;

  select hwid into current_hwid from public.profiles where id = auth.uid();
  if current_hwid is not null then
    raise exception 'An HWID is already bound. Reset it first.';
  end if;

  update public.profiles set hwid = upper(new_hwid) where id = auth.uid();
end;
$$;

-- 5. Reset the hardware ID, enforcing a cooldown.
--    Change the interval here AND in js/config.js (HWID_RESET_COOLDOWN_DAYS)
--    to match.
create or replace function public.reset_hwid()
returns timestamptz
language plpgsql
security definer set search_path = public
as $$
declare
  cooldown interval := interval '7 days';
  last_reset timestamptz;
begin
  select hwid_reset_at into last_reset from public.profiles where id = auth.uid();

  if last_reset is not null and now() - last_reset < cooldown then
    raise exception 'HWID was reset recently. Try again after %',
      to_char(last_reset + cooldown, 'YYYY-MM-DD HH24:MI UTC');
  end if;

  update public.profiles
    set hwid = null, hwid_reset_at = now()
    where id = auth.uid();

  insert into public.hwid_resets (user_id) values (auth.uid());
  return now();
end;
$$;

-- 6. Save a license key on the account (the offline, signed ANTI-... keys).
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

-- 7. Regenerate the client token (invalidates the old one immediately).
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

-- 8. Called directly by the Minecraft client — NOT by a logged-in browser.
--    The token itself is the credential, so this runs for the "anon" role with
--    no user session. First use from a PC binds that PC's HWID; later calls
--    must match, matching server/server.mjs's /api/client/verify exactly.
create or replace function public.client_verify(token text, hwid text)
returns jsonb
language plpgsql
security definer set search_path = public
as $$
declare
  row_id uuid;
  row_hwid text;
  row_tier text;
  hwid_up text := upper(coalesce(hwid, ''));
begin
  if hwid_up !~ '^[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$' then
    return jsonb_build_object('ok', false, 'tier', 'FREE', 'error', 'Malformed HWID.');
  end if;

  select id, hwid, tier into row_id, row_hwid, row_tier
    from public.profiles where client_token = token;

  if row_id is null then
    return jsonb_build_object('ok', false, 'tier', 'FREE', 'error', 'That token isn''t valid.');
  end if;

  if row_hwid is null then
    update public.profiles set hwid = hwid_up where id = row_id;
  elsif row_hwid <> hwid_up then
    return jsonb_build_object('ok', false, 'tier', 'FREE', 'error',
      'This token is bound to a different PC. Reset your HWID on the dashboard to move it here.');
  end if;

  return jsonb_build_object('ok', true, 'tier', upper(row_tier), 'error', null);
end;
$$;

-- 9. Grants. client_verify is callable by the public "anon" key (the mod has
--    no Supabase login) — everything else needs a signed-in user.
grant execute on function public.set_hwid(text)             to authenticated;
grant execute on function public.reset_hwid()                to authenticated;
grant execute on function public.set_license_key(text)       to authenticated;
grant execute on function public.regenerate_client_token()   to authenticated;
grant execute on function public.client_verify(text, text)   to anon, authenticated;

-- Backfill profiles for any users that already existed before this ran.
insert into public.profiles (id, email)
  select id, email from auth.users
  on conflict (id) do nothing;
