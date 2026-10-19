INSERT INTO categories (id, parent_id, slug, name, position) VALUES
  ('beverages', NULL, 'beverages', 'Beverages', 1),
  ('tea', 'beverages', 'tea', 'Tea', 2),
  ('coffee', 'beverages', 'coffee', 'Coffee', 3);

INSERT INTO products (id, category_id, sku, name, description, price_cents, stock, status) VALUES
  ('assam', 'tea', 'ASSAM', 'Assam', 'Malty black tea.', 1299, 20, 'active'),
  ('ceylon', 'tea', 'CEYLON', 'Ceylon', 'Bright black tea.', 1499, 15, 'active'),
  ('espresso', 'coffee', 'ESPRESSO', 'Espresso', 'Dark roast for espresso.', 999, 30, 'active');
