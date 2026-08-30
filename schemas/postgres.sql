-- schema.sql

-- Create the 'users' table
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create the 'products' table with more complex structure
CREATE TABLE IF NOT EXISTS products (
  id SERIAL PRIMARY KEY,
  sku VARCHAR(50) NOT NULL UNIQUE,
  name VARCHAR(255) NOT NULL,
  description TEXT NULL,
  price DECIMAL(10, 2) DEFAULT 0.00,
  stock_count INTEGER DEFAULT 0,
  is_active BOOLEAN DEFAULT TRUE,
  created_by VARCHAR(100), -- Could store user ID/sub
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


DROP TRIGGER IF EXISTS update_products_updated_at ON products;
DROP FUNCTION IF EXISTS update_updated_at_column();
DROP TRIGGER IF EXISTS before_product_update ON products;
DROP FUNCTION IF EXISTS validate_product_update();
DROP TRIGGER IF EXISTS after_product_insert ON products;
DROP FUNCTION IF EXISTS products_insert_response();
DROP FUNCTION IF EXISTS get_my_products();
DROP FUNCTION IF EXISTS do_something(TEXT);
DROP FUNCTION IF EXISTS teapot();
DROP FUNCTION IF EXISTS invalidate_users();
DROP FUNCTION IF EXISTS custom_headers();

-- Create a trigger function to update updated_at timestamp
CREATE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create trigger for products table
CREATE TRIGGER update_products_updated_at
    BEFORE UPDATE ON products
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Create a function to validate product updates
CREATE OR REPLACE FUNCTION validate_product_update()
RETURNS TRIGGER AS $$
BEGIN
    -- Check if the user making the request (current_setting('request.claims'))
    -- is the one who created the product.
    -- Allow update only if they match OR if the user is an admin
    IF OLD.created_by != (current_setting('request.claims', TRUE)::json->>'sub')
       AND (current_setting('request.claims', TRUE)::json->>'role') != 'admin' THEN
        -- If trying to update restricted fields
        RAISE EXCEPTION 'Authorization failed: You can only modify products you created.';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for product validation
CREATE TRIGGER before_product_update
    BEFORE UPDATE ON products
    FOR EACH ROW
    EXECUTE FUNCTION validate_product_update();

-- Create a function that returns products for current user
CREATE FUNCTION get_my_products()
RETURNS SETOF products AS $$
BEGIN
    RETURN QUERY
    SELECT *
    FROM products
    WHERE created_by = (current_setting('request.claims', TRUE)::json->>'sub');
END;
$$ LANGUAGE plpgsql;

-- Create a simple function for testing
CREATE FUNCTION do_something(json_param TEXT)
RETURNS TEXT AS $$
BEGIN
    RETURN 'Processed: ' || json_param;
END;
$$ LANGUAGE plpgsql;

-- PostgREST-style response GUC: harvested into DBPlugin ctx before COMMIT
CREATE FUNCTION teapot()
RETURNS TEXT AS $$
BEGIN
    PERFORM set_config('response.status', '418', true);
    PERFORM set_config('response.headers', '[{"Set-Cookie":"test=123"}]', true);
    RETURN 'I''m a teapot';
END;
$$ LANGUAGE plpgsql;

-- Harvested as cache.invalidate so cache middleware can bump table/view ETags
CREATE FUNCTION invalidate_users()
RETURNS TEXT AS $$
BEGIN
    PERFORM set_config('cache.invalidate', 'users,products', true);
    RETURN 'ok';
END;
$$ LANGUAGE plpgsql;

CREATE FUNCTION products_insert_response()
RETURNS TRIGGER AS $$
BEGIN
    PERFORM set_config('response.headers', '[{"X-Inserted":"1"}]', true);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER after_product_insert
    AFTER INSERT ON products
    FOR EACH ROW
    EXECUTE FUNCTION products_insert_response();

-- Optional db.pre-request / db.post-request hook (SELECT custom_headers())
CREATE FUNCTION custom_headers()
RETURNS void AS $$
BEGIN
    PERFORM set_config('response.headers', '[{"X-Hook":"1"}]', true);
END;
$$ LANGUAGE plpgsql;
