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
DROP FUNCTION IF EXISTS get_my_products();
DROP FUNCTION IF EXISTS do_something(TEXT);

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
