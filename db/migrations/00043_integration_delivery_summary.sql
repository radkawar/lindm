-- SPDX-License-Identifier: Apache-2.0

-- +goose Up
-- Delivered rows are the bulk of the table; the console summary counts recent
-- deliveries per destination and reads the latest delivery time from this index.
CREATE INDEX integration_deliveries_delivered ON integration_deliveries(destination_id, delivered_at) WHERE status = 3;

-- +goose Down
DROP INDEX integration_deliveries_delivered;
