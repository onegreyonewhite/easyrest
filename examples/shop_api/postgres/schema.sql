CREATE ROLE shop_owner NOLOGIN;
CREATE ROLE shop_conn LOGIN PASSWORD 'shop_conn' NOSUPERUSER NOBYPASSRLS;

CREATE SCHEMA shop AUTHORIZATION shop_owner;
GRANT USAGE ON SCHEMA shop TO shop_conn;
GRANT CREATE ON SCHEMA public TO shop_conn;

CREATE TABLE shop.carts (
  id text PRIMARY KEY,
  owner text NOT NULL,
  status text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX carts_one_open ON shop.carts (owner) WHERE status = 'open';

CREATE TABLE shop.cart_items (
  id text PRIMARY KEY,
  cart_id text NOT NULL REFERENCES shop.carts (id),
  product_id text NOT NULL,
  sku text NOT NULL,
  title text NOT NULL,
  unit_price integer NOT NULL,
  quantity integer NOT NULL
);

CREATE TABLE shop.inventory (
  id text PRIMARY KEY,
  available integer NOT NULL
);

CREATE TABLE shop.orders (
  id text PRIMARY KEY,
  owner text NOT NULL,
  status text NOT NULL,
  total_cents integer NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE shop.order_items (
  id text PRIMARY KEY,
  order_id text NOT NULL REFERENCES shop.orders (id),
  product_id text NOT NULL,
  sku text NOT NULL,
  title text NOT NULL,
  unit_price integer NOT NULL,
  quantity integer NOT NULL
);

ALTER TABLE shop.carts OWNER TO shop_owner;
ALTER TABLE shop.cart_items OWNER TO shop_owner;
ALTER TABLE shop.inventory OWNER TO shop_owner;
ALTER TABLE shop.orders OWNER TO shop_owner;
ALTER TABLE shop.order_items OWNER TO shop_owner;

CREATE FUNCTION shop.current_sub() RETURNS text
LANGUAGE sql STABLE
SET search_path = shop, public AS $$
  SELECT coalesce(
    CASE
      WHEN coalesce(current_setting('request.claims', true), '') = '' THEN NULL
      ELSE current_setting('request.claims', true)::jsonb ->> 'sub'
    END,
    ''
  );
$$;

CREATE FUNCTION shop.has_scope(wanted text) RETURNS boolean
LANGUAGE sql STABLE
SET search_path = shop, public AS $$
  SELECT EXISTS (
    SELECT 1
    FROM regexp_split_to_table(
      coalesce(
        CASE
          WHEN coalesce(current_setting('request.claims', true), '') = '' THEN ''
          ELSE current_setting('request.claims', true)::jsonb ->> 'scope'
        END,
        ''
      ),
      '\s+'
    ) AS token
    WHERE token = wanted
  );
$$;

CREATE FUNCTION shop.pre_request() RETURNS void
LANGUAGE plpgsql
SET search_path = shop, public AS $$
BEGIN
  IF current_setting('request.method', true) IN ('POST', 'PUT', 'PATCH', 'DELETE')
     AND shop.current_sub() = '' THEN
    PERFORM set_config('response.status', '403', true);
  END IF;
END;
$$;

CREATE FUNCTION shop.my_cart() RETURNS text
LANGUAGE plpgsql
SET search_path = shop, public AS $$
DECLARE
  who text := shop.current_sub();
  method text := coalesce(current_setting('request.method', true), '');
  row shop.carts%ROWTYPE;
BEGIN
  IF who = '' THEN
    PERFORM set_config('response.status', '403', true);
    RETURN json_build_object('error', 'sign in required')::text;
  END IF;
  SELECT * INTO row FROM shop.carts
  WHERE owner = who AND status = 'open'
  ORDER BY created_at
  LIMIT 1;
  IF NOT FOUND THEN
    IF method <> 'POST' THEN
      PERFORM set_config('response.status', '404', true);
      RETURN json_build_object('error', 'no open cart')::text;
    END IF;
    BEGIN
      INSERT INTO shop.carts (id, owner, status)
      VALUES (gen_random_uuid()::text, who, 'open')
      RETURNING * INTO row;
    EXCEPTION WHEN unique_violation THEN
      SELECT * INTO row FROM shop.carts
      WHERE owner = who AND status = 'open'
      LIMIT 1;
    END;
  END IF;
  RETURN json_build_object('id', row.id, 'status', row.status)::text;
END;
$$;

CREATE FUNCTION shop.add_item(
  cart_id text,
  product_id text,
  quantity double precision,
  sku text,
  title text,
  unit_price double precision
) RETURNS text
LANGUAGE plpgsql
SET search_path = shop, public AS $$
DECLARE
  who text := shop.current_sub();
  cart shop.carts%ROWTYPE;
  item_id text;
  qty integer;
  price integer;
BEGIN
  IF who = '' THEN
    PERFORM set_config('response.status', '403', true);
    RETURN json_build_object('error', 'sign in required')::text;
  END IF;
  IF product_id IS NULL OR btrim(product_id) = ''
     OR sku IS NULL OR btrim(sku) = ''
     OR title IS NULL OR btrim(title) = ''
     OR quantity IS NULL OR quantity <> trunc(quantity) OR quantity <= 0
     OR unit_price IS NULL OR unit_price <> trunc(unit_price) OR unit_price < 0 THEN
    PERFORM set_config('response.status', '409', true);
    RETURN json_build_object('error', 'invalid item')::text;
  END IF;
  qty := quantity::integer;
  price := unit_price::integer;
  SELECT * INTO cart FROM shop.carts WHERE carts.id = add_item.cart_id FOR UPDATE;
  IF NOT FOUND THEN
    PERFORM set_config('response.status', '404', true);
    RETURN json_build_object('error', 'cart not found')::text;
  END IF;
  IF cart.status <> 'open' THEN
    PERFORM set_config('response.status', '409', true);
    RETURN json_build_object('error', 'cart is not open')::text;
  END IF;
  item_id := gen_random_uuid()::text;
  INSERT INTO shop.cart_items (id, cart_id, product_id, sku, title, unit_price, quantity)
  VALUES (item_id, cart.id, product_id, sku, title, price, qty);
  RETURN json_build_object(
    'item_id', item_id,
    'cart_id', cart.id,
    'product_id', product_id,
    'sku', sku,
    'title', title,
    'unit_price', price,
    'quantity', qty
  )::text;
END;
$$;

CREATE FUNCTION shop.checkout(id text) RETURNS text
LANGUAGE plpgsql
SET search_path = shop, public AS $$
DECLARE
  who text := shop.current_sub();
  cart shop.carts%ROWTYPE;
  item shop.cart_items%ROWTYPE;
  order_id text;
  total integer := 0;
  avail integer;
  req jsonb;
  location text;
BEGIN
  IF who = '' THEN
    PERFORM set_config('response.status', '403', true);
    RETURN json_build_object('error', 'sign in required')::text;
  END IF;
  SELECT * INTO cart FROM shop.carts WHERE carts.id = checkout.id FOR UPDATE;
  IF NOT FOUND THEN
    PERFORM set_config('response.status', '404', true);
    RETURN json_build_object('error', 'cart not found')::text;
  END IF;
  IF cart.status <> 'open' THEN
    PERFORM set_config('response.status', '409', true);
    RETURN json_build_object('error', 'cart is not open')::text;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM shop.cart_items WHERE cart_items.cart_id = cart.id) THEN
    PERFORM set_config('response.status', '409', true);
    RETURN json_build_object('error', 'cart is empty')::text;
  END IF;
  FOR item IN
    SELECT * FROM shop.cart_items WHERE cart_items.cart_id = cart.id ORDER BY cart_items.id
  LOOP
    SELECT inventory.available INTO avail
    FROM shop.inventory
    WHERE inventory.id = item.product_id
    FOR UPDATE;
    IF NOT FOUND OR avail < item.quantity THEN
      PERFORM set_config('response.status', '409', true);
      RETURN json_build_object('error', 'insufficient inventory')::text;
    END IF;
  END LOOP;
  order_id := gen_random_uuid()::text;
  FOR item IN
    SELECT * FROM shop.cart_items WHERE cart_items.cart_id = cart.id ORDER BY cart_items.id
  LOOP
    total := total + item.unit_price * item.quantity;
  END LOOP;
  INSERT INTO shop.orders (id, owner, status, total_cents)
  VALUES (order_id, who, 'placed', total);
  FOR item IN
    SELECT * FROM shop.cart_items WHERE cart_items.cart_id = cart.id ORDER BY cart_items.id
  LOOP
    UPDATE shop.inventory
    SET available = available - item.quantity
    WHERE inventory.id = item.product_id;
    INSERT INTO shop.order_items (id, order_id, product_id, sku, title, unit_price, quantity)
    VALUES (gen_random_uuid()::text, order_id, item.product_id, item.sku, item.title, item.unit_price, item.quantity);
  END LOOP;
  UPDATE shop.carts SET status = 'checked_out' WHERE carts.id = cart.id;
  IF coalesce(current_setting('request.request', true), '') = '' THEN
    req := '{}'::jsonb;
  ELSE
    req := current_setting('request.request', true)::jsonb;
  END IF;
  location := coalesce(req->>'scheme', 'https') || '://' || coalesce(req->>'host', 'localhost')
    || '/restapi/v1/orders/' || order_id || '/';
  PERFORM set_config('response.status', '201', true);
  PERFORM set_config(
    'response.headers',
    json_build_array(json_build_object('Location', location))::text,
    true
  );
  PERFORM set_config('cache.invalidate', 'inventory,carts,cart_items,orders,order_items', true);
  RETURN json_build_object('order_id', order_id, 'status', 'placed', 'total_cents', total)::text;
END;
$$;

CREATE FUNCTION shop.pay_order(id text) RETURNS text
LANGUAGE plpgsql
SET search_path = shop, public AS $$
DECLARE
  row shop.orders%ROWTYPE;
BEGIN
  IF shop.current_sub() = '' THEN
    PERFORM set_config('response.status', '403', true);
    RETURN json_build_object('error', 'sign in required')::text;
  END IF;
  SELECT * INTO row FROM shop.orders WHERE orders.id = pay_order.id FOR UPDATE;
  IF NOT FOUND THEN
    PERFORM set_config('response.status', '404', true);
    RETURN json_build_object('error', 'order not found')::text;
  END IF;
  IF row.status <> 'placed' THEN
    PERFORM set_config('response.status', '409', true);
    RETURN json_build_object('error', 'invalid status')::text;
  END IF;
  UPDATE shop.orders SET status = 'paid' WHERE orders.id = row.id;
  RETURN json_build_object('order_id', row.id, 'status', 'paid')::text;
END;
$$;

CREATE FUNCTION shop.ship_order(id text) RETURNS text
LANGUAGE plpgsql
SET search_path = shop, public AS $$
DECLARE
  row shop.orders%ROWTYPE;
BEGIN
  IF NOT shop.has_scope('orders-manage') THEN
    PERFORM set_config('response.status', '403', true);
    RETURN json_build_object('error', 'forbidden')::text;
  END IF;
  SELECT * INTO row FROM shop.orders WHERE orders.id = ship_order.id FOR UPDATE;
  IF NOT FOUND THEN
    PERFORM set_config('response.status', '404', true);
    RETURN json_build_object('error', 'order not found')::text;
  END IF;
  IF row.status <> 'paid' THEN
    PERFORM set_config('response.status', '409', true);
    RETURN json_build_object('error', 'invalid status')::text;
  END IF;
  UPDATE shop.orders SET status = 'shipped' WHERE orders.id = row.id;
  RETURN json_build_object('order_id', row.id, 'status', 'shipped')::text;
END;
$$;

CREATE FUNCTION shop.cancel_order(id text) RETURNS text
LANGUAGE plpgsql
SET search_path = shop, public AS $$
DECLARE
  row shop.orders%ROWTYPE;
BEGIN
  IF shop.current_sub() = '' THEN
    PERFORM set_config('response.status', '403', true);
    RETURN json_build_object('error', 'sign in required')::text;
  END IF;
  SELECT * INTO row FROM shop.orders WHERE orders.id = cancel_order.id FOR UPDATE;
  IF NOT FOUND THEN
    PERFORM set_config('response.status', '404', true);
    RETURN json_build_object('error', 'order not found')::text;
  END IF;
  IF row.status <> 'placed' THEN
    PERFORM set_config('response.status', '409', true);
    RETURN json_build_object('error', 'invalid status')::text;
  END IF;
  UPDATE shop.orders SET status = 'cancelled' WHERE orders.id = row.id;
  RETURN json_build_object('order_id', row.id, 'status', 'cancelled')::text;
END;
$$;

ALTER TABLE shop.carts ENABLE ROW LEVEL SECURITY;
ALTER TABLE shop.carts FORCE ROW LEVEL SECURITY;
ALTER TABLE shop.cart_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE shop.cart_items FORCE ROW LEVEL SECURITY;
ALTER TABLE shop.inventory ENABLE ROW LEVEL SECURITY;
ALTER TABLE shop.inventory FORCE ROW LEVEL SECURITY;
ALTER TABLE shop.orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE shop.orders FORCE ROW LEVEL SECURITY;
ALTER TABLE shop.order_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE shop.order_items FORCE ROW LEVEL SECURITY;

CREATE POLICY carts_owner ON shop.carts
  USING (owner = shop.current_sub())
  WITH CHECK (owner = shop.current_sub());

CREATE POLICY cart_items_owner ON shop.cart_items
  USING (
    EXISTS (
      SELECT 1 FROM shop.carts
      WHERE carts.id = cart_items.cart_id AND carts.owner = shop.current_sub()
    )
  )
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM shop.carts
      WHERE carts.id = cart_items.cart_id AND carts.owner = shop.current_sub()
    )
  );

CREATE POLICY inventory_all ON shop.inventory
  USING (true)
  WITH CHECK (true);

CREATE POLICY orders_owner ON shop.orders
  USING (owner = shop.current_sub() OR shop.has_scope('orders-manage'))
  WITH CHECK (owner = shop.current_sub() OR shop.has_scope('orders-manage'));

CREATE POLICY order_items_owner ON shop.order_items
  USING (
    EXISTS (
      SELECT 1 FROM shop.orders
      WHERE orders.id = order_items.order_id
        AND (orders.owner = shop.current_sub() OR shop.has_scope('orders-manage'))
    )
  )
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM shop.orders
      WHERE orders.id = order_items.order_id
        AND (orders.owner = shop.current_sub() OR shop.has_scope('orders-manage'))
    )
  );

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA shop TO shop_conn;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA shop TO shop_conn;
