-- users table (master)
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  rut TEXT UNIQUE,
  name TEXT,
  email TEXT,
  embedding BYTEA,      -- encrypted embedding (AES-GCM)
  img BYTEA,            -- encrypted id image
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- audit log
CREATE TABLE IF NOT EXISTS audit (
  id SERIAL PRIMARY KEY,
  event TEXT,
  details TEXT,
  actor TEXT,
  ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- local nodes (registered devices)
CREATE TABLE IF NOT EXISTS nodes (
  id SERIAL PRIMARY KEY,
  node_id TEXT UNIQUE,
  last_seen TIMESTAMP,
  ip TEXT,
  info JSONB
);
