-- pgcrypto (crypt/gen_salt) lives in the "extensions" schema on Supabase, not "public";
-- the previous search_path omitted it, so every RPC below failed at call time.
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
