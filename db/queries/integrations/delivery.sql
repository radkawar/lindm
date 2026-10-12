-- name: CreateDestination :one
INSERT INTO integration_destinations(id, display_name, kind, endpoint, pinned_ca_pem, enabled, secret_ciphertext)
VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *;

-- name: LockDestination :one
SELECT * FROM integration_destinations WHERE id = $1 AND deleted_at IS NULL FOR UPDATE;

-- name: UpdateDestination :one
UPDATE integration_destinations SET display_name=$2, endpoint=$3, pinned_ca_pem=$4, enabled=$5,
  version=version+1, updated_at=clock_timestamp() WHERE id=$1 AND deleted_at IS NULL RETURNING *;

-- name: DeleteDestination :exec
UPDATE integration_destinations SET enabled=false, deleted_at=clock_timestamp(), updated_at=clock_timestamp(),
  version=version+1, secret_ciphertext='',
  previous_secret_ciphertext='', previous_secret_expires_at=NULL WHERE id=$1;

-- name: CancelDestinationDeliveries :exec
UPDATE integration_deliveries SET status=5, lease_token=NULL, lease_expires_at=NULL,
  lease_generation=lease_generation+1, last_error='destination_deleted'
WHERE destination_id=$1 AND status IN (1,2,4);

-- name: RotateDestinationSecret :one
UPDATE integration_destinations SET previous_secret_ciphertext=secret_ciphertext,
  previous_secret_expires_at=sqlc.arg(expires_at), secret_ciphertext=sqlc.arg(ciphertext),
  version=version+1, updated_at=clock_timestamp() WHERE id=sqlc.arg(id) RETURNING *;

-- name: ListDestinations :many
SELECT * FROM integration_destinations WHERE deleted_at IS NULL
  AND (created_at,id) < (sqlc.arg(before_time)::timestamptz,sqlc.arg(before_id)::uuid)
ORDER BY created_at DESC,id DESC LIMIT sqlc.arg(page_limit);

-- name: InsertMutation :exec
INSERT INTO integration_mutations(actor_id, request_id, request_hash) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING;

-- name: LockMutation :one
SELECT * FROM integration_mutations WHERE actor_id=$1 AND request_id=$2 FOR UPDATE;

-- name: CompleteMutation :exec
UPDATE integration_mutations SET response=$3 WHERE actor_id=$1 AND request_id=$2;

-- name: InsertIntegrationAudit :exec
INSERT INTO audit_events(id,actor_id,action,resource_id,reason) VALUES ($1,$2,$3,$4,$5);

-- name: ListDeliveries :many
SELECT * FROM integration_deliveries
WHERE (sqlc.narg(destination_id)::uuid IS NULL OR destination_id=sqlc.narg(destination_id))
  AND (sqlc.arg(status_filter)::integer=0 OR status=sqlc.arg(status_filter))
  AND (NOT sqlc.arg(failures_only)::boolean OR status=4 OR (status IN (1,2) AND last_error<>''))
  AND (sequence,id) < (sqlc.arg(before_sequence)::bigint,sqlc.arg(before_id)::uuid)
ORDER BY sequence DESC,id DESC LIMIT sqlc.arg(page_limit);

-- name: SummarizeDeliveries :many
SELECT d.id AS destination_id,
  (SELECT count(*) FROM integration_deliveries x
    WHERE x.destination_id=d.id AND x.status=3 AND x.delivered_at>=sqlc.arg(delivered_since)::timestamptz)::bigint AS delivered,
  (SELECT max(x.delivered_at) FROM integration_deliveries x
    WHERE x.destination_id=d.id AND x.status=3)::timestamptz AS last_delivered_at,
  (SELECT count(*) FROM integration_deliveries x WHERE x.destination_id=d.id AND x.status=4)::bigint AS failed,
  (SELECT count(*) FROM integration_deliveries x
    WHERE x.destination_id=d.id AND x.status IN (1,2) AND x.last_error<>'')::bigint AS retrying,
  (SELECT count(*) FROM integration_deliveries x
    WHERE x.destination_id=d.id AND x.status IN (1,2) AND x.last_error='')::bigint AS queued,
  COALESCE((SELECT x.last_error FROM integration_deliveries x
    WHERE x.destination_id=d.id AND x.status IN (1,2,4) AND x.last_error<>''
    ORDER BY x.sequence DESC LIMIT 1), '')::text AS last_error
FROM integration_destinations d WHERE d.deleted_at IS NULL
ORDER BY d.created_at DESC,d.id DESC LIMIT 100;

-- name: LockDelivery :one
SELECT * FROM integration_deliveries WHERE id=$1 FOR UPDATE;

-- name: ReplayDelivery :one
UPDATE integration_deliveries SET status=1,attempts=0,replay_count=replay_count+1,
  next_attempt_at=clock_timestamp(),last_error='',lease_token=NULL,lease_expires_at=NULL,
  lease_generation=lease_generation+1 WHERE id=$1 AND status=4 RETURNING *;

-- name: ExpireExhaustedDeliveries :exec
WITH exhausted AS (
 SELECT id FROM integration_deliveries WHERE status=2 AND lease_expires_at<=clock_timestamp() AND attempts>=10
 ORDER BY lease_expires_at LIMIT 100 FOR UPDATE SKIP LOCKED
)
UPDATE integration_deliveries SET status=4,lease_token=NULL,lease_expires_at=NULL,last_error='lease_expired'
WHERE id IN (SELECT id FROM exhausted);

-- name: ClaimDelivery :one
WITH candidate AS (
 SELECT d.id FROM integration_deliveries d
 JOIN integration_destinations target ON target.id=d.destination_id
 WHERE target.enabled AND target.deleted_at IS NULL AND d.attempts<10
   AND ((d.status=1 AND d.next_attempt_at<=clock_timestamp()) OR (d.status=2 AND d.lease_expires_at<=clock_timestamp()))
   AND NOT EXISTS (SELECT 1 FROM integration_deliveries earlier
     WHERE earlier.destination_id=d.destination_id AND earlier.resource_id=d.resource_id
       AND earlier.sequence<d.sequence AND earlier.status IN (1,2,4))
 ORDER BY d.sequence,d.id LIMIT 1 FOR UPDATE OF d SKIP LOCKED
)
UPDATE integration_deliveries SET status=2, attempts=attempts+1, lease_token=sqlc.arg(lease_token),
  lease_generation=lease_generation+1,lease_expires_at=clock_timestamp()+interval '60 seconds'
WHERE id IN (SELECT id FROM candidate) RETURNING *;

-- name: LoadDeliveryTarget :one
SELECT * FROM integration_destinations WHERE id=$1 AND enabled AND deleted_at IS NULL;

-- name: LoadEvent :one
SELECT * FROM integration_events WHERE id=$1;

-- name: CompleteDelivery :execrows
UPDATE integration_deliveries SET status=3,delivered_at=clock_timestamp(),lease_token=NULL,lease_expires_at=NULL,last_error=''
WHERE id=sqlc.arg(id) AND status=2 AND lease_token=sqlc.arg(lease_token)
 AND lease_generation=sqlc.arg(lease_generation) AND lease_expires_at>clock_timestamp();

-- name: FailDelivery :execrows
UPDATE integration_deliveries SET status=CASE WHEN attempts>=10 THEN 4 ELSE 1 END,
  next_attempt_at=clock_timestamp()+sqlc.arg(delay_seconds)::double precision*interval '1 second',
  last_error=sqlc.arg(last_error),lease_token=NULL,lease_expires_at=NULL
WHERE id=sqlc.arg(id) AND status=2 AND lease_token=sqlc.arg(lease_token)
 AND lease_generation=sqlc.arg(lease_generation) AND lease_expires_at>clock_timestamp();

-- name: RefreshComplianceEvents :exec
SELECT integration_refresh_due_compliance();
