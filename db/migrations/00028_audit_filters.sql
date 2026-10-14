-- SPDX-License-Identifier: Apache-2.0

-- Audit search metadata is separate from the original hash-bound audit payload.
-- +goose Up
-- +goose StatementBegin
CREATE FUNCTION audit_action_category(action text, capability text) RETURNS smallint
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT CASE
    WHEN action = 'recovery_key.reveal' THEN 1
    WHEN action IN ('device_action.create', 'device_action.start', 'device_action.result',
                    'device_action.recovery_handoff', 'device_action.recovery_start',
                    'device_action.recovery_checkpoint', 'device_action.recovery_result')
      AND capability IN ('device.crypto-erase.v1', 'device.sanitize.v1') THEN 2
    WHEN action IN ('assistance.request', 'assistance.prompt', 'assistance.consent',
                    'assistance.join', 'assistance.answer', 'assistance.start',
                    'assistance.stop', 'assistance.end') THEN 3
    ELSE 0
  END::smallint;
$$;
-- +goose StatementEnd

-- These actions store a device UUID directly in resource_id. Do not infer a
-- device from an arbitrary resource UUID (for example a device group or grant).
-- Explicit structured targets remain authoritative when present.
-- +goose StatementBegin
CREATE FUNCTION audit_direct_device_target(action text, resource_id text) RETURNS uuid
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT CASE
    WHEN action IN ('device.enroll', 'device.revoke', 'device.renew',
                    'device.activate', 'device.recovery_hold',
                    'device.recovery_authorized', 'device.recovered',
                    'provisioning.reserve', 'provisioning.approve')
      AND resource_id ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    THEN resource_id::uuid
    ELSE NULL
  END;
$$;
-- +goose StatementEnd

CREATE TABLE audit_event_search (
  event_id uuid PRIMARY KEY REFERENCES audit_events(id),
  sequence bigint NOT NULL UNIQUE REFERENCES report_audit_rows(sequence),
  occurred_at timestamptz NOT NULL,
  actor_id uuid,
  target_device_id uuid,
  action_category smallint NOT NULL CHECK (action_category BETWEEN 0 AND 3)
);
CREATE INDEX audit_search_keyset ON audit_event_search(occurred_at DESC, event_id DESC);
CREATE INDEX audit_search_actor_keyset ON audit_event_search(actor_id, occurred_at DESC, event_id DESC);
CREATE INDEX audit_search_target_keyset ON audit_event_search(target_device_id, occurred_at DESC, event_id DESC);
CREATE INDEX audit_search_category_keyset ON audit_event_search(action_category, occurred_at DESC, event_id DESC);
CREATE INDEX audit_actor_name_prefix ON principals USING spgist(lower(display_name));
CREATE INDEX audit_device_name_prefix ON devices USING spgist(lower(hostname));

LOCK TABLE audit_events IN SHARE ROW EXCLUSIVE MODE;
INSERT INTO audit_event_search
SELECT a.id, r.sequence, a.occurred_at, a.actor_id,
       COALESCE(a.target_device_id, audit_direct_device_target(a.action, a.resource_id), d.device_id),
       audit_action_category(a.action, d.capability)
FROM audit_events a
JOIN report_audit_rows r ON r.event_id = a.id
LEFT JOIN device_actions d ON d.id::text = a.resource_id
  AND (a.action LIKE 'device_action.%' OR a.action IN ('recovery_key.reveal', 'local_admin.reveal'));

-- Capture after report_audit_capture (PostgreSQL orders same-kind triggers by name).
-- Metadata is frozen at admission; later action state changes cannot change a page.
-- +goose StatementBegin
CREATE FUNCTION audit_capture_search() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE target uuid; action_capability text; audit_sequence bigint;
BEGIN
  IF NEW.action LIKE 'device_action.%' OR NEW.action IN ('recovery_key.reveal', 'local_admin.reveal') THEN
    SELECT device_id, capability INTO target, action_capability
    FROM device_actions WHERE id::text = NEW.resource_id;
  END IF;
  SELECT sequence INTO STRICT audit_sequence FROM report_audit_rows WHERE event_id = NEW.id;
  INSERT INTO audit_event_search VALUES
    (NEW.id, audit_sequence, NEW.occurred_at, NEW.actor_id,
     COALESCE(NEW.target_device_id, audit_direct_device_target(NEW.action, NEW.resource_id), target),
     audit_action_category(NEW.action, action_capability));
  RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER zz_audit_search_capture AFTER INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION audit_capture_search();
CREATE TRIGGER audit_search_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON audit_event_search FOR EACH STATEMENT EXECUTE FUNCTION report_audit_immutable();
-- Action UUID lookup must remain indexed for the pre-existing text resource IDs.
CREATE INDEX device_actions_audit_resource ON device_actions((id::text));

ALTER TABLE report_artifacts DROP CONSTRAINT report_artifacts_kind_check;
ALTER TABLE report_artifacts ADD CONSTRAINT report_artifacts_kind_check CHECK (kind BETWEEN 1 AND 5);
ALTER TABLE report_artifacts ADD COLUMN audit_filter bytea NOT NULL DEFAULT '';
ALTER TABLE report_artifacts ADD COLUMN audit_max_events integer NOT NULL DEFAULT 100000 CHECK (audit_max_events BETWEEN 1 AND 100000);

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
  ALTER TABLE report_artifacts DROP COLUMN audit_max_events;
  ALTER TABLE report_artifacts DROP COLUMN audit_filter;
  ALTER TABLE report_artifacts DROP CONSTRAINT report_artifacts_kind_check;
  ALTER TABLE report_artifacts ADD CONSTRAINT report_artifacts_kind_check CHECK (kind BETWEEN 1 AND 4);
  DROP TRIGGER zz_audit_search_capture ON audit_events;
  DROP FUNCTION audit_capture_search();
  DROP TABLE audit_event_search;
  DROP FUNCTION audit_action_category(text, text);
  DROP FUNCTION audit_direct_device_target(text, text);
  DROP INDEX device_actions_audit_resource;
  DROP INDEX audit_actor_name_prefix;
  DROP INDEX audit_device_name_prefix;
END $$;
-- +goose StatementEnd
