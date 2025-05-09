-- schema.sql

-- Create the 'users' table
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create the 'products' table
CREATE TABLE IF NOT EXISTS products (
  id INT AUTO_INCREMENT PRIMARY KEY,
  sku VARCHAR(50) NOT NULL UNIQUE,
  name VARCHAR(255) NOT NULL,
  description TEXT NULL,
  price DECIMAL(10, 2) DEFAULT 0.00,
  stock_count INT DEFAULT 0,
  is_active BOOLEAN DEFAULT TRUE,
  created_by VARCHAR(100), -- Could store user ID/sub
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Create a stored procedure 'doSomething'
DROP FUNCTION IF EXISTS doSomething;
DROP FUNCTION IF EXISTS getMyProducts;
DROP TRIGGER IF EXISTS before_product_update;
DELIMITER //
CREATE FUNCTION doSomething(jsonParam TEXT)
RETURNS TEXT
DETERMINISTIC                -- или NO SQL, если функция не использует таблицы
BEGIN
    RETURN CONCAT('Processed: ', jsonParam);
END;
//

CREATE FUNCTION getMyProducts()
RETURNS JSON
DETERMINISTIC
READS SQL DATA -- Important: Indicates the function reads data
BEGIN
    DECLARE result JSON;
    SELECT JSON_ARRAYAGG(JSON_OBJECT(
            'id', id,
            'sku', sku,
            'name', name,
            'price', price,
            'stock_count', stock_count,
            'is_active', is_active,
            'created_at', created_at
           ))
    INTO result
    FROM products
    WHERE created_by = @request_claims_sub; -- Session variable works here!

    RETURN COALESCE(result, JSON_ARRAY()); -- Return empty array if no results
END;
//

CREATE TRIGGER before_product_update
BEFORE UPDATE ON products
FOR EACH ROW
BEGIN
    -- Check if the user making the request (@request_claims_sub)
    -- is the one who created the product.
    -- Allow update only if they match OR if the user is an admin (e.g., from a role claim)
    IF OLD.created_by != @request_claims_sub AND @request_claims_role != 'admin' THEN
        -- If trying to update restricted fields
        IF NEW.name != OLD.name OR NEW.description != OLD.description THEN
             SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Authorization failed: You can only modify products you created.';
        END IF;
    END IF;
END;
//

DELIMITER ;
