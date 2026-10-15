# SPDX-License-Identifier: Apache-2.0
"""Controlled helper tests, not native PostgreSQL or AWS qualification."""

import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import ANY, Mock, patch


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


class PrivateCommandDiagnosticTest(unittest.TestCase):
    def test_failed_child_output_is_private_and_not_relayed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "installer-diagnostic.private"
            with patch.object(INSTALL, "protected") as protected, patch.object(INSTALL.os, "fchown") as chown:
                with self.assertRaises(INSTALL.InstallError) as result:
                    INSTALL.command(
                        ["/bin/sh", "-c", "printf 'private stdout marker'; printf 'private stderr marker' >&2; exit 7"],
                        diagnostic_path=path,
                    )
            protected.assert_called_once_with(str(path.parent), directory=True, private=True)
            chown.assert_called_once_with(ANY, 0, 0)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.stat().st_nlink, 1)
            self.assertEqual(path.read_text(), "private stdout markerprivate stderr marker")
            self.assertNotIn("private stdout marker", str(result.exception))
            self.assertNotIn("private stderr marker", str(result.exception))
            self.assertIn("exit 7", str(result.exception))

    def test_existing_file_or_symlink_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "existing.private"
            target.write_text("retained original")
            link = Path(directory) / "linked.private"
            link.symlink_to(target)
            for path in (target, link):
                with self.subTest(path=path.name), patch.object(INSTALL, "protected"), patch.object(INSTALL.subprocess, "run") as run:
                    with self.assertRaises(FileExistsError):
                        INSTALL.command(["/bin/sh"], diagnostic_path=path)
                    run.assert_not_called()
                    self.assertEqual(target.read_text(), "retained original")

    def test_private_diagnostic_cannot_be_captured_in_memory(self):
        with patch.object(INSTALL.subprocess, "run") as run:
            with self.assertRaises(INSTALL.InstallError):
                INSTALL.command(["/bin/sh"], capture=True, diagnostic_path="/root/diagnostic.private")
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
