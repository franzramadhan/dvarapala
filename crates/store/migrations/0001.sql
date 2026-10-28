-- RFC 0010: dvarapala shared state. Counters are UNLOGGED: no WAL, not
-- replicated, emptied after a crash or failover, which only means local
-- limits for at most one window.
CREATE SCHEMA IF NOT EXISTS dvarapala;

CREATE TABLE IF NOT EXISTS dvarapala.schema_version (
  version integer PRIMARY KEY,
  applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNLOGGED TABLE IF NOT EXISTS dvarapala.counters (
  cluster text NOT NULL,
  key text NOT NULL,
  window_start bigint NOT NULL,
  count bigint NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (cluster, key, window_start)
);
CREATE INDEX IF NOT EXISTS counters_expires_at ON dvarapala.counters (expires_at);

CREATE UNLOGGED TABLE IF NOT EXISTS dvarapala.heartbeats (
  cluster text NOT NULL,
  replica text NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (cluster, replica)
);

-- kind: 'heavy' (key is a CIDR) or 'pause' (key is a destination name)
CREATE UNLOGGED TABLE IF NOT EXISTS dvarapala.marks (
  cluster text NOT NULL,
  kind text NOT NULL,
  key text NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (cluster, kind, key)
);
CREATE INDEX IF NOT EXISTS marks_expires_at ON dvarapala.marks (expires_at);
