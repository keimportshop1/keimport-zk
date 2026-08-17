-- ============================================================
-- FIX DEFINITIVO (v4) - corrección del bug de colisión "l"
-- Error: record "l" has no field "disponible" / is not assigned yet
-- Causa: la variable PL/pgSQL "l" chocaba con el alias "l" en
--   sum(l.disponible) from _calcular_lotes() l
-- Solución: alias renombrado a "lo".
-- 1) Elimina TODAS las sobrecargas viejas
-- 2) Crea registrar_venta + _calcular_lotes corregidos
-- 3) Crea _diag_fifo (test FIFO)
-- PEGA ESTO EN Supabase > SQL Editor y ejecutalo.
-- ============================================================

do $$
declare r record;
begin
  for r in select p.oid::regprocedure::text as sig
           from pg_catalog.pg_proc p
           where p.proname in ('registrar_venta', '_calcular_lotes', '_diag_fifo')
             and p.pronamespace = 'public'::regnamespace
  loop
    execute 'drop function public.' || r.sig;
  end loop;
end $$;

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

  select coalesce(sum(lo.disponible), 0)::numeric into v_disp from public._calcular_lotes() lo;

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
-- DIAGNOSTICO: replica el loop FIFO sin insertar nada.
create or replace function public._diag_fifo()
returns jsonb
language plpgsql security definer
set search_path = public
as $$
declare
  l record;
  v_disp numeric := 0;
  v_rest numeric := 3;
  v_used numeric;
  v_consumo jsonb := '[]';
begin
  select coalesce(sum(lo.disponible), 0)::numeric into v_disp from public._calcular_lotes() lo;
  for l in select * from public._calcular_lotes() loop
    if v_rest <= 0 then exit; end if;
    if l.disponible > 0 then
      v_used := least(v_rest, l.disponible);
      v_consumo := v_consumo || jsonb_build_object(
        'compraId', l.compra_id::text, 'cantidad', v_used, 'tasa', l.tasa, 'fecha', l.fecha);
      v_rest := v_rest - v_used;
    end if;
  end loop;
  return jsonb_build_object('ok', true, 'v_disp', v_disp, 'consumo', v_consumo, 'restante', v_rest);
exception when others then
  return jsonb_build_object('ok', false, 'msg', SQLERRM, 'sqlstate', SQLSTATE);
end;
$$;
grant execute on function public.registrar_venta(text, text, text, text, text, text, text, text, text, text, text, numeric, numeric, numeric, numeric, numeric, text, text, jsonb, boolean) to anon;
grant execute on function public._calcular_lotes() to anon;
grant execute on function public._diag_fifo() to anon;