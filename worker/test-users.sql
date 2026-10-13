-- local test data for test.js (never run against the real database)
DELETE FROM kv; DELETE FROM users;
INSERT INTO users (sid, data, updated) VALUES
  ('76561198000000001', '{"steamId":"76561198000000001","name":"Test Owner","avatar":""}', 0),
  ('76561198000000002', '{"steamId":"76561198000000002","name":"Test Pilot","avatar":""}', 0);
