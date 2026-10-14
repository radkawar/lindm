-- SPDX-License-Identifier: Apache-2.0

-- +goose Up
-- Expiring work claims distribute pending advisory evaluations across replicas.
-- A claim is an efficiency boundary only: each evaluation still binds its device
-- under the device row lock and exact snapshot/feed revisions, so an expired or
-- overlapping claim can repeat work but never publish an incoherent evaluation.
CREATE TABLE advisory_evaluation_claims (
  device_id uuid PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
  lease_token uuid NOT NULL,
  lease_until timestamptz NOT NULL
);
CREATE INDEX advisory_evaluation_claims_token_idx ON advisory_evaluation_claims(lease_token);

-- +goose Down
DROP TABLE advisory_evaluation_claims;
