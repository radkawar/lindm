# SPDX-License-Identifier: Apache-2.0
"""Controlled version-gate tests, not native PostgreSQL or AWS qualification."""

import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock, patch


SPEC = importlib.util.spec_from_file_location(
    "aws_install_external_db", Path(__file__).with_name("install-external-db.py")
)
INSTALL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALL)


class BackupClientsTest(unittest.TestCase):
    def admin(self, version):
        admin = Mock()
        admin.execute.return_value.fetchone.return_value = (str(version),)
        return admin

    def test_postgresql16_with_matching_native_clients(self):
        admin = self.admin(160013)
        with patch.object(INSTALL, "command", side_effect=[
            b"pg_dump (PostgreSQL) 16.13 (Ubuntu)",
            b"pg_restore (PostgreSQL) 16.13 (Ubuntu)",
        ]):
            INSTALL.backup_clients(admin)
        admin.execute.assert_called_once_with("SHOW server_version_num")

    def test_other_database_majors_stop_before_clients_or_mutation(self):
        for version in (150013, 170009, 180006):
            with self.subTest(version=version):
                admin = self.admin(version)
                with patch.object(INSTALL, "command") as command:
                    with self.assertRaisesRegex(INSTALL.InstallError, "PostgreSQL 16 only"):
                        INSTALL.backup_clients(admin)
                    command.assert_not_called()
                admin.execute.assert_called_once_with("SHOW server_version_num")

    def test_either_older_newer_or_unrecognized_client_is_refused(self):
        valid = b"pg_dump (PostgreSQL) 16.13"
        for binary in (0, 1):
            for invalid in (b"pg_dump (PostgreSQL) 15.16", b"pg_dump (PostgreSQL) 18.6", b"unrecognized version"):
                with self.subTest(binary=binary, invalid=invalid):
                    versions = [valid, valid]
                    versions[binary] = invalid
                    admin = self.admin(160013)
                    with patch.object(INSTALL, "command", side_effect=versions):
                        with self.assertRaisesRegex(INSTALL.InstallError, "PostgreSQL 16 pg_dump and pg_restore"):
                            INSTALL.backup_clients(admin)
                    admin.execute.assert_called_once_with("SHOW server_version_num")

    def test_missing_client_diagnostic_does_not_relay_original_error(self):
        with patch.object(INSTALL, "command", side_effect=OSError("private diagnostic marker")):
            with self.assertRaises(INSTALL.InstallError) as result:
                INSTALL.backup_clients(self.admin(160013))
        self.assertNotIn("private diagnostic marker", str(result.exception))
        self.assertIn("PostgreSQL 16 backup clients are required", str(result.exception))


if __name__ == "__main__":
    unittest.main()
