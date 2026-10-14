-- SPDX-License-Identifier: Apache-2.0

-- +goose Up
-- The remote-assistance setting each device's executor reports with every
-- assistance sync, using lindm.agent.v1.AssistanceEnablement numbers. No row: the
-- agent has not reported one. changed_at is when the reported value changed.
CREATE TABLE assistance_device_policies (
    device_id uuid PRIMARY KEY REFERENCES devices(id),
    policy smallint NOT NULL CHECK (policy IN (1, 2)),
    changed_at timestamptz NOT NULL
);

-- +goose Down
DROP TABLE assistance_device_policies;
