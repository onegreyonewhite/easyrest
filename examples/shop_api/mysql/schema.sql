CREATE TABLE categories (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  parent_id VARCHAR(64) NULL,
  slug VARCHAR(64) NOT NULL,
  name VARCHAR(255) NOT NULL,
  position INT NOT NULL,
  CONSTRAINT categories_parent_fk FOREIGN KEY (parent_id) REFERENCES categories (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE products (
  id VARCHAR(64) NOT NULL PRIMARY KEY,
  category_id VARCHAR(64) NOT NULL,
  sku VARCHAR(64) NOT NULL,
  name VARCHAR(255) NOT NULL,
  description TEXT NULL,
  price_cents INT NOT NULL,
  stock INT NOT NULL,
  status VARCHAR(32) NOT NULL,
  image VARCHAR(1024) NULL,
  CONSTRAINT products_category_fk FOREIGN KEY (category_id) REFERENCES categories (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
