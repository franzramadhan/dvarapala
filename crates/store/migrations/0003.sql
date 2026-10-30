-- RFC 0024: LLM labels (RFC 0023), one row per model answer. Logged, as the
-- history: it is training data. features: the [ml] features as an object.
CREATE TABLE IF NOT EXISTS dvarapala.llm_labels (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cluster text NOT NULL,
  replica text NOT NULL,
  at bigint NOT NULL,
  trigger text NOT NULL,
  route text NOT NULL,
  method text NOT NULL,
  path text NOT NULL,
  label text NOT NULL,
  confidence double precision NOT NULL,
  pattern text NOT NULL,
  features jsonb
);
CREATE INDEX IF NOT EXISTS llm_labels_at ON dvarapala.llm_labels (cluster, at, id);
CREATE INDEX IF NOT EXISTS llm_labels_label ON dvarapala.llm_labels (cluster, label, at);
