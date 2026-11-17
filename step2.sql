-- Agent Shompa · Step 2 · database setup
-- Run once in Supabase → SQL Editor → New query → paste → Run.
-- Uses the SAME Supabase project as Agent Saila, so both apps share one login and data.
-- Safe to run again: it only creates what is missing.

create extension if not exists supabase_vault;

-- 1. Websites ---------------------------------------------------------------
create table if not exists public.shompa_sites (
  id          uuid primary key default gen_random_uuid(),
  owner       uuid not null default auth.uid() references auth.users(id) on delete cascade,
  domain      text not null,
  site_type   text not null default 'other' check (site_type in ('textile','other')),
  author_name text,
  wp_username text,
  connector_version text,
  created_at  timestamptz not null default now(),
  deleted_at  timestamptz,
  unique (owner, domain)
);

-- 2. Social accounts and which website posts where -------------------------
create table if not exists public.shompa_social_accounts (
  id         uuid primary key default gen_random_uuid(),
  owner      uuid not null default auth.uid() references auth.users(id) on delete cascade,
  platform   text not null,            -- facebook, pinterest, x, linkedin, tumblr, reddit …
  name       text not null,            -- e.g. "Practical Textile Facebook Page"
  ai_posts   boolean not null default false, -- true = 2 AI posts a day (Facebook, Pinterest)
  created_at timestamptz not null default now()
);

create table if not exists public.shompa_site_social (
  site_id    uuid not null references public.shompa_sites(id) on delete cascade,
  account_id uuid not null references public.shompa_social_accounts(id) on delete cascade,
  owner      uuid not null default auth.uid() references auth.users(id) on delete cascade,
  primary key (site_id, account_id)
);

-- 3. General settings (AI choice etc.) --------------------------------------
create table if not exists public.shompa_settings (
  owner       uuid primary key default auth.uid() references auth.users(id) on delete cascade,
  ai_provider text not null default 'claude' check (ai_provider in ('claude','openai','gemini')),
  ai_model    text,
  updated_at  timestamptz not null default now()
);

-- 4. Secrets: passwords and API keys -----------------------------------------
-- The real value goes into Supabase Vault (encrypted). This table only says
-- WHICH secrets exist and when they were saved — never the value itself.
create table if not exists public.shompa_secret_index (
  owner      uuid not null default auth.uid() references auth.users(id) on delete cascade,
  name       text not null,            -- e.g. bing_api_key, wp_app_password, ai_key_claude
  site_id    uuid references public.shompa_sites(id) on delete cascade,
  vault_id   uuid not null,
  updated_at timestamptz not null default now()
);
create unique index if not exists shompa_secret_index_uq
  on public.shompa_secret_index (owner, name, coalesce(site_id, '00000000-0000-0000-0000-000000000000'::uuid));

-- 5. Row level security: each row is visible only to the person who owns it ---
do $$
declare t text;
begin
  foreach t in array array['shompa_sites','shompa_social_accounts','shompa_site_social','shompa_settings','shompa_secret_index'] loop
    execute format('alter table public.%I enable row level security', t);
    execute format('drop policy if exists own_rows on public.%I', t);
    execute format('create policy own_rows on public.%I for all to authenticated using (owner = auth.uid()) with check (owner = auth.uid())', t);
  end loop;
end $$;

-- The secret index may be read, but only written through the function below.
revoke insert, update, delete on public.shompa_secret_index from authenticated;

-- 6. Save a secret (write-only). The app can replace a secret, never read it.
create or replace function public.shompa_save_secret(p_name text, p_value text, p_site uuid default null)
returns timestamptz
language plpgsql
security definer
set search_path = public, vault
as $$
declare
  v_owner uuid := auth.uid();
  v_id    uuid;
  v_key   text;
begin
  if v_owner is null then raise exception 'Please sign in first.'; end if;
  if p_name !~ '^[a-z0-9_]{2,60}$' then raise exception 'Bad secret name.'; end if;
  if coalesce(length(p_value),0) = 0 or length(p_value) > 20000 then raise exception 'Empty or too long.'; end if;
  if p_site is not null and not exists (select 1 from public.shompa_sites where id = p_site and owner = v_owner) then
    raise exception 'Website not found.';
  end if;

  v_key := 'shompa:' || v_owner || ':' || coalesce(p_site::text, 'global') || ':' || p_name;

  select vault_id into v_id from public.shompa_secret_index
   where owner = v_owner and name = p_name and site_id is not distinct from p_site;

  if v_id is null then
    v_id := vault.create_secret(p_value, v_key, 'Agent Shompa');
    insert into public.shompa_secret_index(owner, name, site_id, vault_id) values (v_owner, p_name, p_site, v_id);
  else
    perform vault.update_secret(v_id, p_value);
    update public.shompa_secret_index set updated_at = now()
     where owner = v_owner and name = p_name and site_id is not distinct from p_site;
  end if;
  return now();
end $$;

-- 7. Delete a secret.
create or replace function public.shompa_delete_secret(p_name text, p_site uuid default null)
returns void
language plpgsql
security definer
set search_path = public, vault
as $$
declare v_id uuid;
begin
  select vault_id into v_id from public.shompa_secret_index
   where owner = auth.uid() and name = p_name and site_id is not distinct from p_site;
  if v_id is null then return; end if;
  delete from vault.secrets where id = v_id;
  delete from public.shompa_secret_index
   where owner = auth.uid() and name = p_name and site_id is not distinct from p_site;
end $$;

revoke all on function public.shompa_save_secret(text,text,uuid)  from public, anon;
revoke all on function public.shompa_delete_secret(text,uuid)     from public, anon;
grant execute on function public.shompa_save_secret(text,text,uuid)  to authenticated;
grant execute on function public.shompa_delete_secret(text,uuid)     to authenticated;
