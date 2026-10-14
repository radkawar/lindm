-- SPDX-License-Identifier: Apache-2.0

-- +goose Up
-- Rolling distributions report OS-update backends PACMAN (4, Arch Linux) and
-- ZYPPER (5, openSUSE Tumbleweed). The original bound admitted only APT and
-- DNF, so every host observation carrying their patch status failed the check
-- and the device synchronization was refused as a whole.
ALTER TABLE host_patch_status DROP CONSTRAINT host_patch_status_backend_check;
ALTER TABLE host_patch_status ADD CONSTRAINT host_patch_status_backend_check CHECK (backend BETWEEN 0 AND 5);

-- +goose Down
DELETE FROM host_patch_status WHERE backend > 3;
ALTER TABLE host_patch_status DROP CONSTRAINT host_patch_status_backend_check;
ALTER TABLE host_patch_status ADD CONSTRAINT host_patch_status_backend_check CHECK (backend BETWEEN 0 AND 3);
