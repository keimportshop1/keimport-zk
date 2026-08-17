-- ============================================================
-- KEIMPORT - MigraciÃ³n a Supabase como base PRINCIPAL
-- Ejecutar una sola vez en: Supabase Dashboard > SQL Editor
-- ============================================================
-- Reescribe las escrituras de la app para que todo pase por
-- Procedimientos almacenados (seguros) y deje Google Sheets
-- Ãºnicamente como respaldo de escritura.
-- ============================================================

create extension if not exists pgcrypto;

-- ------------------------------------------------------------
-- TABLAS
-- ------------------------------------------------------------

create table if not exists public.usuarios (
  username   text primary key,
  pass_hash  text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.sesiones (
  token          text primary key,
  username       text not null references public.usuarios(username) on delete cascade,
  dispositivo    text not null default '',
  creada_en      timestamptz not null default now(),
  ultimo_latido  timestamptz not null default now(),
  estado         text not null default 'activa' check (estado in ('activa','superada','cerrada'))
);
create index if not exists idx_sesiones_username on public.sesiones(username);

create table if not exists public.plataformas (
  id         text primary key,
  nombre     text not null,
  moneda     text not null default 'USD',
  saldo      numeric not null default 0,
  updated_at timestamptz not null default now()
);

create table if not exists public.config (
  uid             integer primary key default 1 check (uid = 1),
  exchange_rate   numeric not null default 40,
  ranges          jsonb not null default '[]',
  clear_marker    jsonb not null default '{}',
  movimientos     jsonb not null default '[]',
  method_map      jsonb not null default '{}',
  updated_at      timestamptz not null default now(),
  last_sale_at    timestamptz,
  last_purchase_at timestamptz,
  last_client_at  timestamptz,
  last_platform_at timestamptz,
  last_clear_at   timestamptz
);

create table if not exists public.clientes (
  cedula         text primary key,
  nombre         text not null default '',
  contacto       text not null default '',
  banco          text not null default '',
  last4          text not null default '',
  last4_alt      text not null default '',
  creado_en      timestamptz not null default now(),
  actualizado_en timestamptz not null default now()
);

create table if not exists public.ventas (
  id          uuid primary key default gen_random_uuid(),
  fecha       text not null,
  hora        text not null default '',
  date_display text not null default '',
  cliente     text not null,
  cedula      text not null default '',
  contacto    text not null default '',
  banco       text not null default '',
  last4       text not null default '',
  last4_alt   text not null default '',
  concepto    text not null default '',
  net_usd     numeric not null,
  comision    numeric not null default 0,
  total_usd   numeric not null,
  total_ves   numeric not null,
  tasa_cambio numeric not null default 0,
  metodo      text not null default '',
  plataforma  text not null default '',
  vendedor    text not null default '',
  movimientos jsonb not null default '[]',
  lotes_consumidos jsonb not null default '[]',
  creado_en   timestamptz not null default now()
);
create index if not exists idx_ventas_fecha on public.ventas(fecha);
alter table public.ventas add column if not exists lotes_consumidos jsonb not null default '[]';

create table if not exists public.compras (
  id         uuid primary key default gen_random_uuid(),
  fecha      text not null,
  hora       text not null default '',
  proveedor  text not null,
  monto_usd  numeric not null,
  tasa_cambio numeric not null default 0,
  monto_ves  numeric not null,
  metodo     text not null default '',
  plataforma text not null default '',
  pago_movil text not null default '',
  titular    text not null default '',
  forma_pago text not null default 'VES',
  referencia text not null default '',
  comprador  text not null default '',
  creado_en  timestamptz not null default now()
);
create index if not exists idx_compras_fecha on public.compras(fecha);

insert into public.config (uid) values (1) on conflict (uid) do nothing;

-- Plataformas por defecto
insert into public.plataformas (id, nombre, moneda, saldo) values
  ('zinli', 'Zinli', 'USD', 0),
  ('usdt', 'USDT', 'USD', 0),
  ('mercantil-panama', 'Mercantil PanamÃ¡', 'USD', 0),
  ('bs', 'BolÃ­vares', 'VES', 0),
  ('efectivo-usd', 'Efectivo USD', 'USD', 0)
on conflict (id) do nothing;

-- Usuario de rescate (Clave: Sudo1234)
insert into public.usuarios (username, pass_hash) values
  ('sudo', encode(digest('keimport::Sudo1234', 'sha256'), 'hex'))
on conflict (username) do nothing;

-- ------------------------------------------------------------
-- RLS: nadie toca las tablas directamente; todo va por RPC.
-- ------------------------------------------------------------
alter table public.usuarios   enable row level security;
alter table public.sesiones   enable row level security;
alter table public.plataformas enable row level security;
alter table public.config     enable row level security;
alter table public.clientes   enable row level security;
alter table public.ventas     enable row level security;
alter table public.compras    enable row level security;

revoke all on table public.usuarios    from anon, authenticated;
revoke all on table public.sesiones    from anon, authenticated;
revoke all on table public.plataformas from anon, authenticated;
revoke all on table public.config      from anon, authenticated;
revoke all on table public.clientes    from anon, authenticated;
revoke all on table public.ventas      from anon, authenticated;
revoke all on table public.compras     from anon, authenticated;

-- ------------------------------------------------------------
-- VALIDACIÃ“N DE SESIÃ“N (usada por todos los RPC seguros)
-- ------------------------------------------------------------
create or replace function public._sesion_valida(p_token text)
returns table (ok boolean, username text, estado text, last_ts timestamptz)
language plpgsql security definer
set search_path = public
as $$
declare
  v_row public.sesiones%rowtype;
begin
  select * into v_row from public.sesiones where token = p_token limit 1;
  if not found then
    return query select false, ''::text, 'invalida'::text, null::timestamptz;
  else
    return query select (v_row.estado = 'activa'), v_row.username, v_row.estado, v_row.ultimo_latido;
  end if;
end;
$$;

-- ------------------------------------------------------------
-- AUTENTICACIÃ“N
-- ------------------------------------------------------------
create or replace function public.login(p_username text, p_hash text, p_dispositivo text default '')
returns jsonb
language plpgsql security definer
set search_path = public
as $$
declare
  v_user public.usuarios%rowtype;
  v_token text := gen_random_uuid()::text || gen_random_uuid()::text;
begin
  select * into v_user from public.usuarios
   where username = lower(btrim(p_username)) limit 1;
  if not found then
    return jsonb_build_object('ok', false, 'msg', 'El usuario no existe.');
  end if;
  if v_user.pass_hash <> p_hash then
    return jsonb_build_object('ok', false, 'msg', 'ContraseÃ±a incorrecta.');
  end if;
  -- SesiÃ³n Ãºnica: invalidar cualquier otra sesiÃ³n activa del mismo usuario
  update public.sesiones set estado = 'superada'
   where username = v_user.username and estado = 'activa';
  insert into public.sesiones (token, username, dispositivo)
  values (v_token, v_user.username, coalesce(p_dispositivo, ''));
  return jsonb_build_object(
    'ok', true,
    'token', v_token,
    'username', v_user.username
  );
end;
$$;

create or replace function public.registrar_usuario(p_username text, p_hash text, p_codigo text)
returns jsonb
language plpgsql security definer
set search_path = public
as $$
begin
  if regexp_replace(coalesce(p_codigo,''), '[^0-9]', '', 'g') <> '87071245' then
    return jsonb_build_object('ok', false, 'msg', 'CÃ³digo de acceso incorrecto. Verifica con el administrador.');
  end if;
  if char_length(p_username) < 3 then
    return jsonb_build_object('ok', false, 'msg', 'El usuario debe tener al menos 3 caracteres.');
  end if;
  insert into public.usuarios (username, pass_hash)
  values (lower(btrim(p_username)), p_hash)
  on conflict (username) do nothing
  returning username into p_username;
  if p_username is null then
    return jsonb_build_object('ok', false, 'msg', 'Ese usuario ya existe.');
  end if;
  return jsonb_build_object('ok', true);
end;
$$;

create or replace function public.cambiar_contrasena(p_username text, p_hash text, p_codigo text)
returns jsonb
language plpgsql security definer
set search_path = public
as $$
begin
  if regexp_replace(coalesce(p_codigo,''), '[^0-9]', '', 'g') <> '87071245' then
    return jsonb_build_object('ok', false, 'msg', 'CÃ³digo de acceso incorrecto. Verifica con el administrador.');
  end if;
  update public.usuarios set pass_hash = p_hash
   where username = lower(btrim(p_username));
  if not found then
    return jsonb_build_object('ok', false, 'msg', 'El usuario no existe.');
  end if;
  -- Forzar cierre en otros dispositivos al cambiar la clave
  update public.sesiones set estado = 'superada'
   where username = lower(btrim(p_username)) and estado = 'activa';
  return jsonb_build_object('ok', true);
end;
$$;

create or replace function public.cerrar_sesion(p_token text)
returns jsonb
language plpgsql security definer
set search_path = public
as $$
begin
  update public.sesiones set estado = 'cerrada' where token = p_token;
  return jsonb_build_object('ok', true);
end;
$$;

-- Elimina un usuario (no permite eliminar la propia cuenta activa)
create or replace function public.eliminar_usuario(p_token text, p_username text)
returns jsonb
language plpgsql security definer
set search_path = public
as $$
declare v_ses record;
begin
  select * into v_ses from public._sesion_valida(p_token);
  if not v_ses.ok then return jsonb_build_object('ok', false, 'estado', v_ses.estado); end if;
  if v_ses.username = lower(btrim(p_username)) then
    return jsonb_build_object('ok', false, 'msg', 'No puedes eliminar tu propia cuenta mientras estás conectado.');
  end if;
  delete from public.usuarios where username = lower(btrim(p_username));
  return jsonb_build_object('ok', true);
end;
$$;

-- ------------------------------------------------------------
-- LECTURAS (siempre despuÃ©s de validar sesiÃ³n)
-- ------------------------------------------------------------
create or replace function public.get_estado(p_token text)
returns jsonb
language plpgsql security definer stable
set search_path = public
as $$
declare
  v_ses record;
  v_cfg public.config%rowtype;
  v_ventas jsonb;
  v_compras jsonb;
  v_clientes jsonb;
  v_plataformas jsonb;
begin
  select * into v_ses from public._sesion_valida(p_token);
  if not v_ses.ok then
    return jsonb_build_object('ok', false, 'estado', v_ses.estado);
  end if;
  select * into v_cfg from public.config where uid = 1;
  select coalesce(jsonb_agg(jsonb_build_object(
      'id', id::text, 'fecha', fecha, 'hora', hora, 'dateDisplay', date_display,
      'client', cliente, 'cedula', cedula, 'contacto', contacto, 'banco', banco,
      'last4', last4, 'last4Alt', last4_alt, 'concept', concepto,
      'netUsd', net_usd, 'commission', comision, 'totalUsd', total_usd,
      'totalVes', total_ves, 'exchangeRate', tasa_cambio,
      'method', metodo, 'platform', plataforma, 'user', vendedor,
      'movements', movimientos, 'lotesConsumidos', lotes_consumidos, 'createdAt', creado_en)
      order by fecha desc, creado_en desc), '[]'::jsonb)
    into v_ventas from public.ventas;
  select coalesce(jsonb_agg(jsonb_build_object(
      'id', id::text, 'fecha', fecha, 'hora', hora,
      'vendor', proveedor, 'usd', monto_usd, 'rate', tasa_cambio, 'totalVes', monto_ves,
      'method', metodo, 'platformIn', plataforma, 'pagoMovil', pago_movil,
      'titular', titular, 'paymentCurrency', forma_pago, 'referencia', referencia,
      'user', comprador, 'createdAt', creado_en)
      order by fecha desc, creado_en desc), '[]'::jsonb)
    into v_compras from public.compras;
  select coalesce(jsonb_agg(jsonb_build_object(
      'id', 'cli_' || cedula, 'cedula', cedula, 'name', nombre, 'contact', contacto, 'bank', banco,
      'last4', last4, 'last4Alt', last4_alt, 'createdAt', creado_en, 'updatedAt', actualizado_en)),
      '[]'::jsonb)
    into v_clientes from public.clientes;
  select coalesce(jsonb_agg(jsonb_build_object(
      'id', id, 'name', nombre, 'currency', moneda, 'initialBalance', saldo,
      'updatedAt', updated_at)), '[]'::jsonb)
    into v_plataformas from public.plataformas;
  return jsonb_build_object(
    'ok', true,
    'ventas', v_ventas,
    'compras', v_compras,
    'clientes', v_clientes,
    'plataformas', v_plataformas,
    'config', jsonb_build_object(
      'exchange_rate', v_cfg.exchange_rate,
      'ranges', v_cfg.ranges,
      'clear_marker', v_cfg.clear_marker,
      'movimientos', v_cfg.movimientos,
      'method_map', v_cfg.method_map,
      'updated_at', v_cfg.updated_at
    ),
    'resumen', jsonb_build_object(
      'last_sale_at', v_cfg.last_sale_at,
      'last_purchase_at', v_cfg.last_purchase_at,
      'last_client_at', v_cfg.last_client_at,
      'last_platform_at', v_cfg.last_platform_at,
      'last_clear_at', v_cfg.last_clear_at
    )
  );
end;
$$;

-- Resumen ligero para el poller (evita descargar todo cada vez)
create or replace function public.get_resumen(p_token text)
returns jsonb
language plpgsql security definer stable
set search_path = public
as $$
declare
  v_ses record;
  v_cfg public.config%rowtype;
begin
  select * into v_ses from public._sesion_valida(p_token);
  if not v_ses.ok then
    return jsonb_build_object('ok', false, 'estado', v_ses.estado);
  end if;
  select * into v_cfg from public.config where uid = 1;
  return jsonb_build_object('ok', true,
    'last_sale_at', v_cfg.last_sale_at,
    'last_purchase_at', v_cfg.last_purchase_at,
    'last_client_at', v_cfg.last_client_at,
    'last_platform_at', v_cfg.last_platform_at,
    'last_clear_at', v_cfg.last_clear_at,
    'exchange_rate', v_cfg.exchange_rate);
end;
$$;

-- ------------------------------------------------------------
-- VENTA ATÃ“MICA (concurrencia segura: 2 vendedores a la vez)
-- En una sola transacciÃ³n: inserta la venta, actualiza saldos de
-- plataformas con bloqueos de fila y hace upsert del cliente.
-- ------------------------------------------------------------
-- Se elimina la firma vieja para evitar ambigÃ¼edad de sobrecarga en PostgREST
drop function if exists public.registrar_venta(text, text, text, text, text, text, text, text, text, text, text, numeric, numeric, numeric, numeric, numeric, text, text, jsonb);

create or replace function public.registrar_venta(
  p_token text,
  p_fecha text,
  p_hora text,
  p_date_display text,
  p_cliente text,
  p_cedula text,
  p_contacto text,
  p_banco text,
  p_last4 text,
  p_last4_alt text,
  p_concepto text,
  p_net_usd numeric,
  p_comision numeric,
  p_total_usd numeric,
  p_total_ves numeric,
  p_tasa numeric,
  p_metodo text,
  p_plataforma text,
  p_movimientos jsonb,
  p_forzar boolean default false
)
returns jsonb
language plpgsql security definer
set search_path = public
as $$
declare
  v_ses record;
  v_id uuid;
  v_plataformas jsonb;
  v_inventario jsonb;
  v_consumo jsonb := '[]';
  v_rest numeric;
  v_disp numeric := 0;
  v_used numeric;
  l record;
  m jsonb;
begin
  select * into v_ses from public._sesion_valida(p_token);
  if not v_ses.ok then
    return jsonb_build_object('ok', false, 'estado', v_ses.estado, 'msg', 'SesiÃ³n invÃ¡lida.');
  end if;

  -- Cliente: upsert
  insert into public.clientes (cedula, nombre, contacto, banco, last4, last4_alt)
  values (coalesce(p_cedula,''), p_cliente, coalesce(p_contacto,''), coalesce(p_banco,''),
          coalesce(p_last4,''), coalesce(p_last4_alt,''))
  on conflict (cedula) do update set
    nombre = excluded.nombre,
    contacto = coalesce(excluded.contacto, public.clientes.contacto),
    banco = coalesce(excluded.banco, public.clientes.banco),
    last4 = coalesce(excluded.last4, public.clientes.last4),
    last4_alt = coalesce(excluded.last4_alt, public.clientes.last4_alt),
    actualizado_en = now();

  -- Movimientos: bloqueo de fila por plataforma (serializa la concurrencia)
  for m in select * from jsonb_array_elements(coalesce(p_movimientos, '[]'::jsonb)) loop
    update public.plataformas
       set saldo = saldo + (m->>'delta')::numeric,
           updated_at = now()
     where id = (m->>'platform')::text;
  end loop;

  -- Consumo de lotes FIFO: se bloquean las compras para serializar
  -- ventas concurrentes de mÃ¡s de un dispositivo.
  for l in select c.id from public.compras c order by c.fecha asc, c.creado_en asc for update loop
    null;
  end loop;

  select coalesce(sum(l.disponible), 0)::numeric into v_disp from public._calcular_lotes() l;

  v_rest := coalesce(p_net_usd, 0);
  for l in select * from public._calcular_lotes() loop
    if v_rest <= 0 then exit; end if;
    if l.disponible > 0 then
      v_used := least(v_rest, l.disponible);
      v_consumo := v_consumo || jsonb_build_object(
        'compraId', l.compra_id::text,
        'cantidad', v_used,
        'tasa', l.tasa,
        'fechaCompra', l.fecha,
        'alerta', case when l.fecha > p_fecha then 'fecha_anterior_a_compra'::text end
      );
      v_rest := v_rest - v_used;
    end if;
  end loop;

  if v_rest > 0 and not coalesce(p_forzar, false) then
    return jsonb_build_object('ok', false, 'estado', 'sin_inventario',
      'msg', 'Inventario insuficiente: hay ' || v_disp::text || ' $ disponibles y faltan ' || v_rest::text || ' $ para esta venta.',
      'requerido', v_rest, 'disponible', v_disp);
  end if;

  if v_rest > 0 then
    v_consumo := v_consumo || jsonb_build_object(
      'compraId', null, 'cantidad', v_rest, 'tasa', 0,
      'alerta', 'inventario_insuficiente');
  end if;

  insert into public.ventas (
    fecha, hora, date_display, cliente, cedula, contacto, banco, last4, last4_alt,
    concepto, net_usd, comision, total_usd, total_ves, tasa_cambio, metodo,
    plataforma, vendedor, movimientos, lotes_consumidos
  ) values (
    p_fecha, coalesce(p_hora,''), coalesce(p_date_display,''), p_cliente,
    coalesce(p_cedula,''), coalesce(p_contacto,''), coalesce(p_banco,''),
    coalesce(p_last4,''), coalesce(p_last4_alt,''), coalesce(p_concepto,''),
    p_net_usd, coalesce(p_comision,0), p_total_usd, p_total_ves, coalesce(p_tasa,0),
    coalesce(p_metodo,''), coalesce(p_plataforma,''), v_ses.username,
    coalesce(p_movimientos,'[]'::jsonb), v_consumo
  ) returning id into v_id;

  update public.config set last_sale_at = now(), updated_at = now() where uid = 1;

  select coalesce(jsonb_agg(jsonb_build_object(
      'id', id, 'name', nombre, 'currency', moneda, 'initialBalance', saldo,
      'updatedAt', updated_at)), '[]'::jsonb)
    into v_plataformas from public.plataformas;

  select coalesce(jsonb_agg(jsonb_build_object(
      'compraId', i.compra_id::text, 'cantidad', i.disponible,
      'tasa', i.tasa, 'fecha', i.fecha)), '[]'::jsonb)
    into v_inventario from public._calcular_lotes() i where i.disponible > 0;

  return jsonb_build_object('ok', true, 'id', v_id::text,
    'plataformas', v_plataformas, 'lotes', v_consumo, 'inventario', v_inventario);
end;
$$;

-- ------------------------------------------------------------
-- COMPRA ATÃ“MICA
-- ------------------------------------------------------------
create or replace function public.registrar_compra(
  p_token text,
  p_fecha text,
  p_hora text,
  p_proveedor text,
  p_monto_usd numeric,
  p_tasa numeric,
  p_monto_ves numeric,
  p_metodo text,
  p_plataforma text,
  p_pago_movil text,
  p_titular text,
  p_forma_pago text,
  p_referencia text,
  p_movimientos jsonb
)
returns jsonb
language plpgsql security definer
set search_path = public
as $$
declare
  v_ses record;
  v_id uuid;
  v_plataformas jsonb;
  m jsonb;
begin
  select * into v_ses from public._sesion_valida(p_token);
  if not v_ses.ok then
    return jsonb_build_object('ok', false, 'estado', v_ses.estado, 'msg', 'SesiÃ³n invÃ¡lida.');
  end if;

  for m in select * from jsonb_array_elements(coalesce(p_movimientos, '[]'::jsonb)) loop
    update public.plataformas
       set saldo = saldo + (m->>'delta')::numeric,
           updated_at = now()
     where id = (m->>'platform')::text;
  end loop;

  insert into public.compras (
    fecha, hora, proveedor, monto_usd, tasa_cambio, monto_ves, metodo,
    plataforma, pago_movil, titular, forma_pago, referencia, comprador
  ) values (
    p_fecha, coalesce(p_hora,''), p_proveedor, p_monto_usd, coalesce(p_tasa,0),
    p_monto_ves, coalesce(p_metodo,''), coalesce(p_plataforma,''),
    coalesce(p_pago_movil,''), coalesce(p_titular,''), coalesce(p_forma_pago,'VES'),
    coalesce(p_referencia,''), v_ses.username
  ) returning id into v_id;

  update public.config set last_purchase_at = now(), updated_at = now() where uid = 1;

  select coalesce(jsonb_agg(jsonb_build_object(
      'id', id, 'name', nombre, 'currency', moneda, 'initialBalance', saldo,
      'updatedAt', updated_at)), '[]'::jsonb)
    into v_plataformas from public.plataformas;

  return jsonb_build_object('ok', true, 'id', v_id::text, 'plataformas', v_plataformas);
end;
$$;

-- ------------------------------------------------------------
-- INVENTARIO POR LOTES (FIFO)
-- Lotes disponibles = compras - consumo ya registrado en ventas.
-- Se ordena por fecha, creado_en: el lote más viejo se consume primero.
-- ------------------------------------------------------------
create or replace function public._calcular_lotes()
returns table (
  compra_id uuid,
  fecha text,
  creado_en timestamptz,
  tasa numeric,
  original numeric,
  disponible numeric
)
language sql security definer stable
set search_path = public
as $$
  with consumido as (
    select (l->>'compraId')::uuid as cid, sum((l->>'cantidad')::numeric) as total
    from public.ventas v, jsonb_array_elements(coalesce(v.lotes_consumidos, '[]'::jsonb)) l
    where (l->>'compraId') is not null
    group by (l->>'compraId')::uuid
  )
  select c.id, c.fecha, c.creado_en, c.tasa_cambio, c.monto_usd,
         c.monto_usd - coalesce(k.total, 0) as disponible
  from public.compras c
  left join consumido k on k.cid = c.id
  order by c.fecha asc, c.creado_en asc;
$$;

-- ------------------------------------------------------------
-- ELIMINACIONES / LIMPIEZA TOTAL
-- ------------------------------------------------------------
create or replace function public.eliminar_venta(p_token text, p_id text)
returns jsonb
language plpgsql security definer
set search_path = public
as $$
declare
  v_ses record;
  v_mov jsonb;
  m jsonb;
begin
  select * into v_ses from public._sesion_valida(p_token);
  if not v_ses.ok then return jsonb_build_object('ok', false, 'estado', v_ses.estado); end if;
  select movimientos into v_mov from public.ventas where id = p_id::uuid;
  -- Revierte el efecto de la venta sobre los saldos antes de borrarla
  for m in select * from jsonb_array_elements(coalesce(v_mov, '[]'::jsonb)) loop
    update public.plataformas
       set saldo = saldo - (m->>'delta')::numeric, updated_at = now()
     where id = (m->>'platform')::text;
  end loop;
  delete from public.ventas where id = p_id::uuid;
  update public.config set last_sale_at = now(), updated_at = now() where uid = 1;
  return jsonb_build_object('ok', true);
end;
$$;

create or replace function public.eliminar_compra(p_token text, p_id text)
returns jsonb
language plpgsql security definer
set search_path = public
as $$
declare
  v_ses record;
  v_compra record;
  v_platout text;
begin
  select * into v_ses from public._sesion_valida(p_token);
  if not v_ses.ok then return jsonb_build_object('ok', false, 'estado', v_ses.estado); end if;
  select monto_usd, monto_ves, plataforma, metodo
    into v_compra from public.compras where id = p_id::uuid;
  if not found then
    return jsonb_build_object('ok', false, 'msg', 'La compra no existe.');
  end if;
  -- Revierte la entrada de USD a la plataforma que la recibió
  update public.plataformas
     set saldo = saldo - v_compra.monto_usd, updated_at = now()
   where id = v_compra.plataforma;
  -- Revierte la salida del método de pago (plataforma según el mapa de métodos)
  select method_map ->> v_compra.metodo into v_platout from public.config where uid = 1;
  if v_platout is not null and v_platout <> '' then
    update public.plataformas
       set saldo = saldo + v_compra.monto_ves, updated_at = now()
     where id = v_platout;
  end if;
  delete from public.compras where id = p_id::uuid;
  update public.config set last_purchase_at = now(), updated_at = now() where uid = 1;
  return jsonb_build_object('ok', true);
end;
$$;

create or replace function public.limpiar_historial(p_token text, p_scope text)
returns jsonb
language plpgsql security definer
set search_path = public
as $$
declare
  v_ses record;
  v_ts bigint := (extract(epoch from now()) * 1000)::bigint;
  v_marker jsonb;
begin
  select * into v_ses from public._sesion_valida(p_token);
  if not v_ses.ok then return jsonb_build_object('ok', false, 'estado', v_ses.estado); end if;

  update public.config set clear_marker =
    clear_marker || jsonb_build_object(p_scope, v_ts),
    last_clear_at = now(), updated_at = now()
  where uid = 1
  returning clear_marker into v_marker;

  if p_scope = 'ventas' then
    delete from public.ventas;
  elsif p_scope = 'compras' then
    delete from public.compras;
  elsif p_scope = 'clientes' then
    delete from public.clientes;
  end if;

  return jsonb_build_object('ok', true, 'marker', v_marker, 'ts', v_ts);
end;
$$;

-- ------------------------------------------------------------
-- CONFIG Y PLATAFORMAS
-- ------------------------------------------------------------
create or replace function public.guardar_cliente(p_token text, p_cliente jsonb)
returns jsonb
language plpgsql security definer
set search_path = public
as $$
declare v_ses record;
begin
  select * into v_ses from public._sesion_valida(p_token);
  if not v_ses.ok then return jsonb_build_object('ok', false, 'estado', v_ses.estado); end if;
  insert into public.clientes (cedula, nombre, contacto, banco, last4, last4_alt)
  values (coalesce(p_cliente->>'cedula',''), coalesce(p_cliente->>'name',''),
          coalesce(p_cliente->>'contact',''), coalesce(p_cliente->>'bank',''),
          coalesce(p_cliente->>'last4',''), coalesce(p_cliente->>'last4Alt',''))
  on conflict (cedula) do update set
    nombre = excluded.nombre, contacto = coalesce(excluded.contacto, public.clientes.contacto),
    banco = coalesce(excluded.banco, public.clientes.banco),
    last4 = coalesce(excluded.last4, public.clientes.last4),
    last4_alt = coalesce(excluded.last4_alt, public.clientes.last4_alt),
    actualizado_en = now();
  update public.config set last_client_at = now(), updated_at = now() where uid = 1;
  return jsonb_build_object('ok', true);
end;
$$;

create or replace function public.eliminar_cliente(p_token text, p_cedula text)
returns jsonb
language plpgsql security definer
set search_path = public
as $$
declare v_ses record;
begin
  select * into v_ses from public._sesion_valida(p_token);
  if not v_ses.ok then return jsonb_build_object('ok', false, 'estado', v_ses.estado); end if;
  delete from public.clientes where cedula = coalesce(p_cedula, '');
  update public.config set last_client_at = now(), updated_at = now() where uid = 1;
  return jsonb_build_object('ok', true);
end;
$$;

create or replace function public.eliminar_plataforma(p_token text, p_id text)
returns jsonb
language plpgsql security definer
set search_path = public
as $$
declare v_ses record;
begin
  select * into v_ses from public._sesion_valida(p_token);
  if not v_ses.ok then return jsonb_build_object('ok', false, 'estado', v_ses.estado); end if;
  delete from public.plataformas where id = p_id;
  update public.config set last_platform_at = now(), updated_at = now() where uid = 1;
  return jsonb_build_object('ok', true);
end;
$$;

create or replace function public.guardar_config(
  p_token text, p_exchange_rate numeric, p_ranges jsonb, p_movimientos jsonb,
  p_method_map jsonb
)
returns jsonb
language plpgsql security definer
set search_path = public
as $$
declare v_ses record;
begin
  select * into v_ses from public._sesion_valida(p_token);
  if not v_ses.ok then return jsonb_build_object('ok', false, 'estado', v_ses.estado); end if;
  update public.config set
    exchange_rate = coalesce(p_exchange_rate, exchange_rate),
    ranges = coalesce(p_ranges, ranges),
    movimientos = coalesce(p_movimientos, movimientos),
    method_map = coalesce(p_method_map, method_map),
    updated_at = now()
  where uid = 1;
  return jsonb_build_object('ok', true);
end;
$$;

create or replace function public.guardar_plataformas(p_token text, p_plataformas jsonb)
returns jsonb
language plpgsql security definer
set search_path = public
as $$
declare
  v_ses record;
  pp jsonb;
  v_saldo_override numeric;
begin
  select * into v_ses from public._sesion_valida(p_token);
  if not v_ses.ok then return jsonb_build_object('ok', false, 'estado', v_ses.estado); end if;
  for pp in select * from jsonb_array_elements(p_plataformas) loop
    -- force_saldo=true (ediciÃ³n manual en Ajustes) sobrescribe el saldo;
    -- si no, se conserva el saldo real del servidor para no pisar la concurrencia.
    v_saldo_override := case when coalesce((pp->>'force_saldo')::boolean, false)
                              then coalesce((pp->>'initialBalance')::numeric, 0)
                              else null end;
    insert into public.plataformas (id, nombre, moneda, saldo)
    values (pp->>'id', coalesce(pp->>'name',''), coalesce(pp->>'currency','USD'),
            coalesce(v_saldo_override, 0))
    on conflict (id) do update set
      nombre = coalesce(excluded.nombre, public.plataformas.nombre),
      moneda = coalesce(excluded.moneda, public.plataformas.moneda),
      saldo = coalesce(v_saldo_override, public.plataformas.saldo),
      updated_at = now();
  end loop;
  update public.config set last_platform_at = now(), updated_at = now() where uid = 1;
  return jsonb_build_object('ok', true);
end;
$$;

-- ------------------------------------------------------------
-- Permisos: anon sÃ³lo ejecuta funciones
-- ------------------------------------------------------------
grant execute on function public.login(text, text, text) to anon;
grant execute on function public.registrar_usuario(text, text, text) to anon;
grant execute on function public.cambiar_contrasena(text, text, text) to anon;
grant execute on function public.cerrar_sesion(text) to anon;
grant execute on function public.eliminar_usuario(text, text) to anon;
grant execute on function public._sesion_valida(text) to anon;
grant execute on function public.get_estado(text) to anon;
grant execute on function public.get_resumen(text) to anon;
grant execute on function public.registrar_venta(text, text, text, text, text, text, text, text, text, text, text, numeric, numeric, numeric, numeric, numeric, text, text, jsonb, boolean) to anon;
grant execute on function public.registrar_compra(text, text, text, text, numeric, numeric, numeric, text, text, text, text, text, text, jsonb) to anon;
grant execute on function public.eliminar_venta(text, text) to anon;
grant execute on function public.eliminar_compra(text, text) to anon;
grant execute on function public.limpiar_historial(text, text) to anon;
grant execute on function public.guardar_cliente(text, jsonb) to anon;
grant execute on function public.eliminar_cliente(text, text) to anon;
grant execute on function public.guardar_config(text, numeric, jsonb, jsonb, jsonb) to anon;
grant execute on function public.guardar_plataformas(text, jsonb) to anon;
grant execute on function public.eliminar_plataforma(text, text) to anon;
-- ------------------------------------------------------------
-- (Opcional) MIGRACIÃ“N DESDE LAS TABLAS ANTIGUAS sales/purchases
-- Copia los registros ya guardados por la integraciÃ³n Supabase
-- anterior si esas tablas existen. Seguro de re-ejecutar.
-- ------------------------------------------------------------
do $$
begin
  if exists (select 1 from information_schema.tables where table_schema='public' and table_name='sales') then
    revoke all on table public.sales from anon, authenticated;
  end if;
  if exists (select 1 from information_schema.tables where table_schema='public' and table_name='purchases') then
    revoke all on table public.purchases from anon, authenticated;
  end if;
end
$$;

do $$
begin
  if exists (select 1 from information_schema.tables where table_schema='public' and table_name='sales') then
    insert into public.ventas (id, fecha, date_display, cliente, net_usd, comision, total_usd, total_ves, tasa_cambio, metodo, plataforma, movimientos, creado_en)
    select (substr(md5('sale|' || id),1,8) || '-' || substr(md5('sale|' || id),9,4) || '-4' || substr(md5('sale|' || id),13,3) || '-' || '8' || substr(md5('sale|' || id),17,3) || '-' || substr(md5('sale|' || id),20,12))::uuid,
           coalesce(fecha, ''), coalesce(fecha, ''), coalesce(cliente, ''), coalesce(recibe_usd, 0), coalesce(comision_usd, 0),
           coalesce(paga_usd, 0), coalesce(paga_ves, 0), coalesce(tasa_cambio, 0),
           coalesce(metodo_pago, ''), coalesce(plataforma, ''),
           case when movimientos is null or movimientos::text = '' then '[]'::jsonb else movimientos::jsonb end,
           coalesce(creado_en, now())
    from public.sales
    on conflict (id) do nothing;
  end if;
end
$$;

do $$
begin
  if exists (select 1 from information_schema.tables where table_schema='public' and table_name='purchases') then
    insert into public.compras (id, fecha, proveedor, monto_usd, tasa_cambio, monto_ves, metodo, plataforma, pago_movil, titular, forma_pago, referencia, creado_en)
    select (substr(md5('buy|' || id),1,8) || '-' || substr(md5('buy|' || id),9,4) || '-4' || substr(md5('buy|' || id),13,3) || '-' || '8' || substr(md5('buy|' || id),17,3) || '-' || substr(md5('buy|' || id),20,12))::uuid,
           coalesce(fecha, ''), coalesce(proveedor, ''), coalesce(monto_usd, 0), coalesce(tasa_cambio, 0),
           coalesce(monto_ves, 0), coalesce(metodo_pago, ''), coalesce(plataforma, ''),
           coalesce(pago_movil, ''), coalesce(titular, ''), coalesce(forma_pago, 'VES'),
           coalesce(referencia, ''), coalesce(creado_en, now())
from public.purchases
     on conflict (id) do nothing;
  end if;
end
$$;

-- ------------------------------------------------------------
-- (Opcional) BACKFILL DE LOTES CONSUMIDOS (FIFO)
-- Rellena lotes_consumidos de las ventas histÃ³ricas (las que estÃ¡n
-- vacÃ­as), reproduciendo el consumo en orden cronolÃ³gico contra las
-- compras. Es idempotente: solo toca ventas sin lotes asignados.
-- ------------------------------------------------------------
do $$
declare
  v_rec record;
  v_consumo jsonb;
  v_rest numeric;
  v_used numeric;
  l record;
begin
  for v_rec in
    select id, fecha, net_usd
    from public.ventas
    where coalesce(lotes_consumidos, '[]'::jsonb) = '[]'::jsonb
    order by fecha asc, creado_en asc
  loop
    v_rest := coalesce(v_rec.net_usd, 0);
    v_consumo := '[]';
    for l in
      with consumido as (
        select (x->>'compraId')::uuid as cid, sum((x->>'cantidad')::numeric) as total
        from public.ventas v, jsonb_array_elements(coalesce(v.lotes_consumidos, '[]'::jsonb)) x
        where (x->>'compraId') is not null
        group by (x->>'compraId')::uuid
      )
      select c.id, c.fecha, c.tasa_cambio, c.monto_usd - coalesce(k.total, 0) as disp
      from public.compras c
      left join consumido k on k.cid = c.id
      order by c.fecha asc, c.creado_en asc
    loop
      if v_rest <= 0 then exit; end if;
      if l.disp > 0 then
        v_used := least(v_rest, l.disp);
        v_consumo := v_consumo || jsonb_build_object(
          'compraId', l.id::text, 'cantidad', v_used, 'tasa', l.tasa_cambio,
          'fechaCompra', l.fecha,
          'alerta', case when l.fecha > v_rec.fecha then 'fecha_anterior_a_compra'::text end
        );
        v_rest := v_rest - v_used;
      end if;
    end loop;
    if v_rest > 0 then
      v_consumo := v_consumo || jsonb_build_object(
        'compraId', null, 'cantidad', v_rest, 'tasa', 0,
        'alerta', 'inventario_insuficiente');
    end if;
    update public.ventas set lotes_consumidos = v_consumo where id = v_rec.id;
  end loop;
end
$$;
