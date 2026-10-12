-- +goose Up
-- Applicability is evaluated against the device's recorded platform facts:
-- 8 = not applicable to this device (never dispatched, excluded from
-- compliance), 9 = waiting for the device to report the facts that decide it.
ALTER TABLE resource_assignment_resources DROP CONSTRAINT resource_assignment_resources_disposition_check;
ALTER TABLE resource_assignment_resources ADD CONSTRAINT resource_assignment_resources_disposition_check CHECK (disposition BETWEEN 1 AND 9);
-- Not-applicable rows leave every compliance projection; a pending row whose
-- dependency is not applicable can never run, so that dependency needs attention.
CREATE OR REPLACE VIEW integration_compliance_projection AS
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
    ) SELECT 1 FROM dependencies WHERE disposition IN (4,5,6,7,8)
  ) AS dependency_attention
FROM resource_assignment_resources r
JOIN resource_assignments a ON a.id = r.assignment_id
JOIN resource_assignment_heads h ON h.assignment_id = a.id AND h.generation_id = a.generation_id
JOIN devices d ON d.id = a.device_id AND d.current_generation_id = a.generation_id
WHERE r.disposition <> 8;

-- +goose Down
CREATE OR REPLACE VIEW integration_compliance_projection AS
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
UPDATE resource_assignment_resources SET disposition = 6, reason = 'resource_capability_evidence_unavailable' WHERE disposition IN (8, 9);
ALTER TABLE resource_assignment_resources DROP CONSTRAINT resource_assignment_resources_disposition_check;
ALTER TABLE resource_assignment_resources ADD CONSTRAINT resource_assignment_resources_disposition_check CHECK (disposition BETWEEN 1 AND 7);
