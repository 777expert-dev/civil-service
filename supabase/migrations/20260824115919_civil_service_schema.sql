-- civil_service schema: public service-card portal + password-gated admin writes
create schema if not exists civil_service;
create extension if not exists pgcrypto;

create table civil_service.service_cards (
  id              text primary key,
  icon            text,
  title           text not null,
  description     text not null default '',
  category        text,
  color_index     integer not null default 0,
  link_url        text not null default '#',
  is_new          boolean not null default false,
  requires_login  boolean not null default false,
  sort_order      integer not null default 0,
  updated_at      timestamptz not null default now()
);

-- public, non-secret key/value config (e.g. 'notice', 'portal_id')
create table civil_service.settings (
  key         text primary key,
  value       text,
  updated_at  timestamptz not null default now()
);

-- password hashes only; never exposed via RLS/grants, only touched by SECURITY DEFINER RPCs below
create table civil_service.admin_credentials (
  id             text primary key,
  password_hash  text not null,
  updated_at     timestamptz not null default now()
);

alter table civil_service.service_cards   enable row level security;
alter table civil_service.settings        enable row level security;
alter table civil_service.admin_credentials enable row level security;

-- anyone can read the public portal content
create policy service_cards_public_read on civil_service.service_cards for select using (true);
create policy settings_public_read      on civil_service.settings      for select using (true);
-- no policies at all on admin_credentials: zero direct client access (read or write) via PostgREST

-- belt-and-suspenders: even with RLS, don't grant table-level write access to API roles.
-- All mutations must go through the password-checked RPCs below.
revoke insert, update, delete on civil_service.service_cards, civil_service.settings, civil_service.admin_credentials
  from anon, authenticated;
revoke select on civil_service.admin_credentials from anon, authenticated;

grant usage on schema civil_service to anon, authenticated;
grant select on civil_service.service_cards, civil_service.settings to anon, authenticated;

-- check id/password against the stored bcrypt hash
create or replace function civil_service.verify_portal(p_id text, p_pw text)
returns boolean
language plpgsql
security definer
set search_path = civil_service, public, extensions
as $$
declare
  v_hash text;
begin
  select password_hash into v_hash from civil_service.admin_credentials where id = p_id;
  if v_hash is null then
    return false;
  end if;
  return v_hash = crypt(p_pw, v_hash);
end;
$$;

-- change the admin id/password; requires the CURRENT password to already match.
-- there is no "bootstrap when empty" path -- the seed migration always inserts one
-- admin row first, so this RPC can never be used for an anonymous first-write takeover.
create or replace function civil_service.save_portal(p_id text, p_new_pw text, p_current_pw text)
returns boolean
language plpgsql
security definer
set search_path = civil_service, public, extensions
as $$
declare
  v_current_id   text;
  v_current_hash text;
begin
  select id, password_hash into v_current_id, v_current_hash
  from civil_service.admin_credentials
  limit 1;

  if v_current_hash is null or v_current_hash <> crypt(p_current_pw, v_current_hash) then
    return false;
  end if;

  update civil_service.admin_credentials
    set id = p_id, password_hash = crypt(p_new_pw, gen_salt('bf')), updated_at = now()
    where id = v_current_id;

  insert into civil_service.settings (key, value, updated_at)
  values ('portal_id', p_id, now())
  on conflict (key) do update set value = excluded.value, updated_at = now();

  return true;
end;
$$;

-- replace all service cards in one transaction; password-gated
create or replace function civil_service.save_cards(p_id text, p_pw text, p_cards jsonb)
returns boolean
language plpgsql
security definer
set search_path = civil_service, public, extensions
as $$
begin
  if not civil_service.verify_portal(p_id, p_pw) then
    return false;
  end if;

  delete from civil_service.service_cards
  where id not in (select value ->> 'id' from jsonb_array_elements(p_cards));

  insert into civil_service.service_cards
    (id, icon, title, description, category, color_index, link_url, is_new, requires_login, sort_order, updated_at)
  select
    value ->> 'id',
    value ->> 'icon',
    value ->> 'title',
    coalesce(value ->> 'description', ''),
    value ->> 'category',
    coalesce((value ->> 'color_index')::int, 0),
    coalesce(value ->> 'link_url', '#'),
    coalesce((value ->> 'is_new')::boolean, false),
    coalesce((value ->> 'requires_login')::boolean, false),
    coalesce((value ->> 'sort_order')::int, 0),
    now()
  from jsonb_array_elements(p_cards)
  on conflict (id) do update set
    icon = excluded.icon,
    title = excluded.title,
    description = excluded.description,
    category = excluded.category,
    color_index = excluded.color_index,
    link_url = excluded.link_url,
    is_new = excluded.is_new,
    requires_login = excluded.requires_login,
    sort_order = excluded.sort_order,
    updated_at = now();

  return true;
end;
$$;

-- upsert a single public setting (e.g. the homepage notice); password-gated
create or replace function civil_service.save_setting(p_id text, p_pw text, p_key text, p_value text)
returns boolean
language plpgsql
security definer
set search_path = civil_service, public, extensions
as $$
begin
  if not civil_service.verify_portal(p_id, p_pw) then
    return false;
  end if;

  insert into civil_service.settings (key, value, updated_at)
  values (p_key, p_value, now())
  on conflict (key) do update set value = excluded.value, updated_at = now();

  return true;
end;
$$;

grant execute on function
  civil_service.verify_portal(text, text),
  civil_service.save_portal(text, text, text),
  civil_service.save_cards(text, text, jsonb),
  civil_service.save_setting(text, text, text, text)
  to anon, authenticated;
