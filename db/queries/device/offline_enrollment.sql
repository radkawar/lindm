-- name: InsertOfflineEnrollmentAuthorization :exec
INSERT INTO offline_enrollment_authorizations (id, token_id, actor_id, request_sha256, authorization_envelope, expires_at)
VALUES ($1, $2, $3, $4, $5, $6);

-- name: GetOfflineEnrollmentAuthorization :one
SELECT * FROM offline_enrollment_authorizations WHERE id = $1;
