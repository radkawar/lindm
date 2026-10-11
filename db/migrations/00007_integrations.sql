-- +goose Up
CREATE TABLE integration_destinations (
  id uuid PRIMARY KEY,
  display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 128),
  kind integer NOT NULL CHECK (kind IN (1, 2)),
  endpoint text NOT NULL CHECK (char_length(endpoint) BETWEEN 1 AND 2048),
  pinned_ca_pem text NOT NULL CHECK (octet_length(pinned_ca_pem) <= 65536),
  enabled boolean NOT NULL,
  secret_ciphertext bytea NOT NULL,
  previous_secret_ciphertext bytea NOT NULL DEFAULT '',
  previous_secret_expires_at timestamptz,
  version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  deleted_at timestamptz,
  CHECK (deleted_at IS NOT NULL OR (kind = 1 AND octet_length(secret_ciphertext) >= 60) OR (kind = 2 AND octet_length(secret_ciphertext) = 0 AND pinned_ca_pem <> ''))
);
CREATE INDEX integration_destinations_page ON integration_destinations(created_at DESC, id DESC) WHERE deleted_at IS NULL;

CREATE TABLE integration_events (
  sequence bigint GENERATED ALWAYS AS IDENTITY NOT NULL UNIQUE,
  id uuid PRIMARY KEY REFERENCES audit_events(id) ON DELETE RESTRICT,
  resource_id text NOT NULL,
  occurred_at timestamptz NOT NULL,
  payload bytea NOT NULL CHECK (octet_length(payload) <= 16384)
);

CREATE TABLE integration_deliveries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  destination_id uuid NOT NULL REFERENCES integration_destinations(id) ON DELETE RESTRICT,
  event_id uuid NOT NULL REFERENCES integration_events(id) ON DELETE RESTRICT,
  sequence bigint NOT NULL,
  resource_id text NOT NULL,
  status integer NOT NULL DEFAULT 1 CHECK (status BETWEEN 1 AND 5),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 10),
  replay_count integer NOT NULL DEFAULT 0 CHECK (replay_count >= 0),
  next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  lease_token uuid,
  lease_generation bigint NOT NULL DEFAULT 0,
  lease_expires_at timestamptz,
  delivered_at timestamptz,
  last_error text NOT NULL DEFAULT '' CHECK (char_length(last_error) <= 64),
  UNIQUE(destination_id, event_id),
  CHECK ((status = 2) = (lease_token IS NOT NULL AND lease_expires_at IS NOT NULL))
);
CREATE INDEX integration_deliveries_claim ON integration_deliveries(next_attempt_at, sequence) WHERE status IN (1, 2);
CREATE INDEX integration_deliveries_order ON integration_deliveries(destination_id, resource_id, sequence) WHERE status IN (1, 2, 4);
CREATE INDEX integration_deliveries_page ON integration_deliveries(sequence DESC, id DESC);

CREATE TABLE integration_mutations (
  actor_id uuid NOT NULL REFERENCES principals(id) ON DELETE RESTRICT,
  request_id uuid NOT NULL,
  request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
  response bytea,
  PRIMARY KEY(actor_id, request_id)
);

-- The trigger is the atomic domain/outbox boundary. Explicit allowlisting drops
-- free-form reasons (potential credentials/PII) and never copies domain payloads.
-- Use the audit chain's commit fence before allocating an outbox sequence.
-- Both AFTER INSERT triggers take the same lock in the same order.
-- +goose StatementBegin
CREATE FUNCTION integration_capture_audit() RETURNS trigger LANGUAGE plpgsql SET timezone = 'UTC' AS $$
DECLARE event_sequence bigint;
BEGIN
  PERFORM singleton FROM report_audit_head WHERE singleton FOR UPDATE;
  INSERT INTO integration_events(id, resource_id, occurred_at, payload)
  VALUES (NEW.id, NEW.resource_id, NEW.occurred_at,
    convert_to(jsonb_build_object('event_id', NEW.id, 'occurred_at', NEW.occurred_at,
      'actor_id', NEW.actor_id, 'action', NEW.action, 'resource_id', NEW.resource_id)::text, 'UTF8'))
  RETURNING sequence INTO event_sequence;
  INSERT INTO integration_deliveries(destination_id, event_id, sequence, resource_id)
  SELECT id, NEW.id, event_sequence, NEW.resource_id FROM integration_destinations
  WHERE enabled AND deleted_at IS NULL;
  RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER integration_audit_outbox AFTER INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION integration_capture_audit();

-- +goose StatementBegin
CREATE FUNCTION integration_immutable_event() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'integration events are immutable';
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER integration_events_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON integration_events FOR EACH STATEMENT EXECUTE FUNCTION integration_immutable_event();

CREATE TABLE report_audit_head (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  chain_id uuid NOT NULL DEFAULT gen_random_uuid(),
  sequence bigint NOT NULL DEFAULT 0 CHECK (sequence >= 0),
  row_hash bytea NOT NULL DEFAULT decode(repeat('00', 32), 'hex') CHECK (octet_length(row_hash) = 32)
);
INSERT INTO report_audit_head (singleton) VALUES (true);
CREATE TABLE report_audit_rows (
  sequence bigint PRIMARY KEY CHECK (sequence > 0),
  event_id uuid NOT NULL UNIQUE,
  previous_hash bytea NOT NULL CHECK (octet_length(previous_hash) = 32),
  row_hash bytea NOT NULL CHECK (octet_length(row_hash) = 32),
  payload bytea NOT NULL CHECK (octet_length(payload) <= 16384)
);
-- The singleton lock is held until the audit transaction commits.
-- +goose StatementBegin
CREATE FUNCTION report_append_audit(event_id uuid, payload bytea) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE head report_audit_head%ROWTYPE; next_hash bytea;
BEGIN
  SELECT * INTO STRICT head FROM report_audit_head WHERE singleton FOR UPDATE;
  next_hash := sha256(convert_to('lindm-audit-v1', 'UTF8') || decode('00', 'hex') || uuid_send(head.chain_id) || int8send(head.sequence + 1) || head.row_hash || payload);
  INSERT INTO report_audit_rows VALUES (head.sequence + 1, event_id, head.row_hash, next_hash, payload);
  UPDATE report_audit_head SET sequence = head.sequence + 1, row_hash = next_hash WHERE singleton;
END;
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION report_capture_audit() RETURNS trigger
LANGUAGE plpgsql SET timezone = 'UTC' AS $$
BEGIN
  PERFORM report_append_audit(NEW.id, convert_to(to_jsonb(NEW)::text, 'UTF8'));
  RETURN NEW;
END;
$$;
-- +goose StatementEnd
LOCK TABLE audit_events IN SHARE ROW EXCLUSIVE MODE;
-- +goose StatementBegin
DO $$
DECLARE event audit_events%ROWTYPE;
BEGIN
  SET LOCAL timezone = 'UTC';
  FOR event IN SELECT * FROM audit_events ORDER BY occurred_at, id LOOP
    PERFORM report_append_audit(event.id, convert_to(to_jsonb(event)::text, 'UTF8'));
  END LOOP;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER report_audit_capture AFTER INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION report_capture_audit();
-- +goose StatementBegin
CREATE FUNCTION report_audit_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit evidence is append only';
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER report_audit_rows_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON report_audit_rows FOR EACH STATEMENT EXECUTE FUNCTION report_audit_immutable();
CREATE TRIGGER report_audit_source_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON audit_events FOR EACH STATEMENT EXECUTE FUNCTION report_audit_immutable();
CREATE TABLE report_schedules (
  id uuid PRIMARY KEY,
  actor_id uuid NOT NULL REFERENCES principals(id),
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 128),
  kind smallint NOT NULL CHECK (kind BETWEEN 1 AND 3),
  format smallint NOT NULL CHECK (format BETWEEN 1 AND 2),
  interval_seconds integer NOT NULL CHECK (interval_seconds BETWEEN 300 AND 31536000),
  retention_days integer NOT NULL CHECK (retention_days BETWEEN 1 AND 3650),
  enabled boolean NOT NULL,
  revision bigint NOT NULL CHECK (revision > 0),
  next_run_at timestamptz NOT NULL DEFAULT now(),
  lease_token uuid,
  lease_until timestamptz
);
CREATE INDEX report_schedules_due ON report_schedules(next_run_at) WHERE enabled;
CREATE TABLE report_artifacts (
  id uuid PRIMARY KEY,
  schedule_id uuid REFERENCES report_schedules(id),
  actor_id uuid NOT NULL REFERENCES principals(id),
  kind smallint NOT NULL CHECK (kind BETWEEN 1 AND 4),
  format smallint NOT NULL CHECK (format BETWEEN 1 AND 3),
  state text NOT NULL DEFAULT 'queued' CHECK (state IN ('queued','building','published','failed')),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  lease_token uuid,
  lease_until timestamptz,
  byte_count bigint NOT NULL DEFAULT 0 CHECK (byte_count BETWEEN 0 AND 33554432),
  row_count bigint NOT NULL DEFAULT 0 CHECK (row_count BETWEEN 0 AND 100000),
  chunk_count integer NOT NULL DEFAULT 0 CHECK (chunk_count BETWEEN 0 AND 128),
  signed_manifest bytea NOT NULL DEFAULT '',
  failure_reason text NOT NULL DEFAULT '',
  after_sequence bigint NOT NULL DEFAULT 0,
  after_hash bytea NOT NULL DEFAULT decode(repeat('00',32),'hex'),
  final_sequence bigint NOT NULL DEFAULT 0,
  final_hash bytea NOT NULL DEFAULT decode(repeat('00',32),'hex'),
  captured_head_sequence bigint NOT NULL DEFAULT 0,
  captured_head_hash bytea NOT NULL DEFAULT decode(repeat('00',32),'hex'),
  chain_id uuid NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000'
);
CREATE INDEX report_artifacts_work ON report_artifacts(created_at) WHERE state IN ('queued','building');
CREATE INDEX report_artifacts_retention ON report_artifacts(expires_at);
CREATE TABLE report_artifact_chunks (
  artifact_id uuid NOT NULL REFERENCES report_artifacts(id) ON DELETE CASCADE,
  chunk_index integer NOT NULL CHECK (chunk_index BETWEEN 0 AND 127),
  data bytea NOT NULL CHECK (octet_length(data) BETWEEN 1 AND 262144),
  PRIMARY KEY(artifact_id,chunk_index)
);
CREATE TABLE report_mutations (
  actor_id uuid NOT NULL REFERENCES principals(id),
  request_id uuid NOT NULL,
  request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
  response bytea NOT NULL,
  PRIMARY KEY(actor_id,request_id)
);

CREATE TABLE integration_compliance_states (
  assignment_id uuid NOT NULL,
  resource_id uuid NOT NULL,
  state text NOT NULL CHECK (state IN ('unknown','attention','stale','drift_remediated','compliant')),
  stale_at timestamptz,
  PRIMARY KEY (assignment_id, resource_id),
  FOREIGN KEY (assignment_id, resource_id) REFERENCES resource_assignment_resources(assignment_id, resource_id)
);
CREATE INDEX integration_compliance_due ON integration_compliance_states(stale_at) WHERE stale_at IS NOT NULL;
-- One normalized projection for event transitions and scheduled reports.
CREATE VIEW integration_compliance_projection AS
SELECT r.*, a.device_id, a.blocked_reason, a.reconcile_interval_seconds,
  EXISTS (
    SELECT 1 FROM resource_actions x
    WHERE x.assignment_id = r.assignment_id AND x.resource_id = r.resource_id
      AND x.closed_at IS NULL AND x.start_authorized_at IS NOT NULL
      AND NOT EXISTS (SELECT 1 FROM resource_actions newer WHERE newer.assignment_id = x.assignment_id AND newer.resource_id = x.resource_id AND newer.resource_sequence > x.resource_sequence)
  ) AS applying,
  EXISTS (
    WITH RECURSIVE dependencies AS (
      SELECT d.resource_id, d.disposition, d.depends_on FROM resource_assignment_resources d
      WHERE r.disposition = 1 AND d.assignment_id = r.assignment_id AND d.resource_id = ANY(r.depends_on)
      UNION
      SELECT d.resource_id, d.disposition, d.depends_on FROM resource_assignment_resources d
      JOIN dependencies parent ON parent.disposition = 1 AND d.resource_id = ANY(parent.depends_on)
      WHERE d.assignment_id = r.assignment_id
    ) SELECT 1 FROM dependencies WHERE disposition IN (4,5,6,7)
  ) AS dependency_attention
FROM resource_assignment_resources r
JOIN resource_assignments a ON a.id = r.assignment_id
JOIN resource_assignment_heads h ON h.assignment_id = a.id AND h.generation_id = a.generation_id
JOIN devices d ON d.id = a.device_id AND d.current_generation_id = a.generation_id;
-- +goose StatementBegin
CREATE FUNCTION integration_refresh_compliance(p_assignment uuid, p_now timestamptz, p_actor uuid) RETURNS void LANGUAGE plpgsql AS $$
DECLARE item record; previous_state text; current_state text; deadline timestamptz;
BEGIN
  PERFORM 1 FROM resource_assignments WHERE id = p_assignment FOR UPDATE;
  FOR item IN
    SELECT * FROM integration_compliance_projection
    WHERE assignment_id = p_assignment ORDER BY position
  LOOP
    deadline := NULL;
    IF item.blocked_reason <> '' OR item.disposition IN (4,5,6,7) OR item.applying OR item.dependency_attention THEN
      current_state := 'attention';
    ELSIF item.last_verified_at IS NULL THEN
      current_state := 'unknown';
    ELSIF p_now >= item.last_verified_at + make_interval(secs => LEAST(2 * item.reconcile_interval_seconds, item.verification_max_age_seconds)) THEN
      current_state := 'stale';
    ELSE
      deadline := item.last_verified_at + make_interval(secs => LEAST(2 * item.reconcile_interval_seconds, item.verification_max_age_seconds));
      current_state := CASE WHEN item.drift_remediated THEN 'drift_remediated' ELSE 'compliant' END;
    END IF;
    SELECT state INTO previous_state FROM integration_compliance_states
      WHERE assignment_id = p_assignment AND resource_id = item.resource_id FOR UPDATE;
    INSERT INTO integration_compliance_states(assignment_id, resource_id, state, stale_at)
      VALUES(p_assignment, item.resource_id, current_state, deadline)
      ON CONFLICT (assignment_id, resource_id) DO UPDATE SET state = EXCLUDED.state, stale_at = EXCLUDED.stale_at;
    IF previous_state IS DISTINCT FROM current_state THEN
      INSERT INTO audit_events(actor_id, action, resource_id, details)
        VALUES(p_actor, 'compliance.state.changed', p_assignment::text || '/' || item.resource_id::text,
          jsonb_build_object('previous_state', COALESCE(previous_state, 'unobserved'), 'state', current_state));
    END IF;
  END LOOP;
  UPDATE integration_compliance_states s SET stale_at = NULL WHERE s.assignment_id = p_assignment
    AND NOT EXISTS (SELECT 1 FROM resource_assignment_heads h JOIN devices d ON d.current_generation_id = h.generation_id WHERE h.assignment_id = p_assignment);
END;
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION integration_capture_compliance() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE assignment uuid;
BEGIN
  IF NEW.action LIKE 'resource_action.%' THEN
    SELECT assignment_id INTO assignment FROM resource_actions WHERE id::text = NEW.resource_id;
  ELSIF NEW.action LIKE 'resource_assignment.%' THEN
    SELECT id INTO assignment FROM resource_assignments WHERE id::text = NEW.resource_id;
  ELSE
    RETURN NEW;
  END IF;
  IF assignment IS NOT NULL THEN
    PERFORM integration_refresh_compliance(assignment, clock_timestamp(), NEW.actor_id);
  END IF;
  RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER integration_compliance_capture AFTER INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION integration_capture_compliance();
-- +goose StatementBegin
CREATE FUNCTION integration_refresh_due_compliance() RETURNS void LANGUAGE plpgsql AS $$
DECLARE assignment record;
BEGIN
  FOR assignment IN
    SELECT a.id FROM resource_assignments a
    WHERE EXISTS (SELECT 1 FROM integration_compliance_states s WHERE s.assignment_id = a.id AND s.stale_at <= clock_timestamp())
    ORDER BY a.id LIMIT 100 FOR UPDATE OF a SKIP LOCKED
  LOOP
    PERFORM integration_refresh_compliance(assignment.id, clock_timestamp(), NULL);
  END LOOP;
END;
$$;
-- +goose StatementEnd
-- Changes without a terminal audit hook still produce a transition. Deferral
-- observes final action/resource evidence, not intermediate writes in a transaction.
-- +goose StatementBegin
CREATE FUNCTION integration_capture_assignment_compliance() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.blocked_reason IS DISTINCT FROM OLD.blocked_reason THEN
    PERFORM integration_refresh_compliance(NEW.id, clock_timestamp(), NULL);
  END IF;
  RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE CONSTRAINT TRIGGER integration_assignment_compliance
AFTER UPDATE ON resource_assignments DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION integration_capture_assignment_compliance();
-- +goose StatementBegin
CREATE FUNCTION integration_capture_action_compliance() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' OR NEW.start_authorized_at IS DISTINCT FROM OLD.start_authorized_at
      OR NEW.closed_at IS DISTINCT FROM OLD.closed_at THEN
    PERFORM integration_refresh_compliance(NEW.assignment_id, clock_timestamp(), NULL);
  END IF;
  RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE CONSTRAINT TRIGGER integration_action_compliance
AFTER INSERT OR UPDATE ON resource_actions DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION integration_capture_action_compliance();

-- +goose Down
DROP TRIGGER integration_action_compliance ON resource_actions;
DROP TRIGGER integration_assignment_compliance ON resource_assignments;
DROP FUNCTION integration_capture_action_compliance();
DROP FUNCTION integration_capture_assignment_compliance();
DROP TRIGGER integration_compliance_capture ON audit_events;
DROP FUNCTION integration_capture_compliance();
DROP FUNCTION integration_refresh_due_compliance();
DROP FUNCTION integration_refresh_compliance(uuid,timestamptz,uuid);
DROP VIEW integration_compliance_projection;
DROP TABLE integration_compliance_states;
DROP TRIGGER integration_events_immutable ON integration_events;
DROP FUNCTION integration_immutable_event();
DROP TRIGGER integration_audit_outbox ON audit_events;
DROP TABLE report_mutations, report_artifact_chunks, report_artifacts, report_schedules;
DROP TRIGGER report_audit_source_immutable ON audit_events;
DROP TRIGGER report_audit_capture ON audit_events;
DROP TABLE report_audit_rows, report_audit_head;
DROP FUNCTION report_audit_immutable();
DROP FUNCTION report_capture_audit();
DROP FUNCTION report_append_audit(uuid, bytea);
DROP FUNCTION integration_capture_audit();
DROP TABLE integration_mutations;
DROP TABLE integration_deliveries;
DROP TABLE integration_events;
DROP TABLE integration_destinations;
