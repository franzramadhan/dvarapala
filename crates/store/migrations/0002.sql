-- RFC 0022: the console's traffic history, one row per replica and minute.
-- A logged table, unlike the RFC 0010 ones: it should survive a failover.
-- counts: requests per verdict (allow, throttle, challenge, drop, error).
CREATE TABLE IF NOT EXISTS dvarapala.traffic_history (
  cluster text NOT NULL,
  minute bigint NOT NULL,
  replica text NOT NULL,
  counts bigint[] NOT NULL,
  PRIMARY KEY (cluster, minute, replica)
);
