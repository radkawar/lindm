#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
"""Root-only, fresh-host AWS installation. Never accept a secret on the CLI."""

import argparse
import ctypes
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import resource
import secrets
import stat
import subprocess
import sys
from urllib.parse import quote, urlencode

import boto3
import psycopg
from psycopg import sql


CHILD_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root",
             "LANG": "C", "LC_ALL": "C", "DEBIAN_FRONTEND": "noninteractive"}
PLUS_UNAVAILABLE = (
    "channel binding is required, but server did not offer an authentication "
    "method that supports channel binding"
)


class InstallError(Exception):
    """Only fixed, nonsecret operator diagnostics may leave this process."""


def protected(path, directory=False, private=False):
    p = Path(path)
    if not p.is_absolute() or ".." in p.parts:
        raise InstallError("Inputs must use absolute paths without parent traversal.")
    for part in [*reversed(p.parents), p]:
        info = part.lstat()
        if info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022:
            raise InstallError("Inputs and their ancestry must be root-owned and not group/world writable.")
        if part != p or directory:
            if not stat.S_ISDIR(info.st_mode):
                raise InstallError("Directory ancestry must not contain symlinks.")
        elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise InstallError("Inputs must be regular files without symlinks or hard links.")
    if private and info.st_mode & 0o077:
        raise InstallError("Private directories and files must exclude group and other access.")
    return p


def read_public(path):
    p = protected(path)
    if p.stat().st_size > 1024 * 1024:
        raise InstallError("Public trust input exceeds 1 MiB.")
    return p.read_bytes()


def create_file(path, data):
    protected(str(Path(path).parent), directory=True, private=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        os.fchown(stream.fileno(), 0, 0)
        os.fchmod(stream.fileno(), 0o600)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def command(arguments, capture=False, diagnostic_path=None):
    # Child argv/environment contain public paths and configuration only. In
    # particular no database connection string, password, or setup code is sent.
    if diagnostic_path is None:
        result = subprocess.run(arguments, env=CHILD_ENV, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, check=False)
    else:
        if capture:
            raise InstallError("Private installer diagnostics cannot also be captured in memory.")
        protected(str(Path(diagnostic_path).parent), directory=True, private=True)
        fd = os.open(diagnostic_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, "wb") as stream:
            os.fchown(stream.fileno(), 0, 0)
            os.fchmod(stream.fileno(), 0o600)
            result = subprocess.run(arguments, env=CHILD_ENV, stdin=subprocess.DEVNULL,
                                    stdout=stream, stderr=subprocess.STDOUT, check=False)
            stream.flush()
            os.fsync(stream.fileno())
    if result.returncode:
        raise InstallError(f"Public {Path(arguments[0]).name} command failed (exit {result.returncode}); output withheld.")
    return result.stdout


def secure_memory():
    if os.geteuid() != 0:
        raise InstallError("Run as root on the fresh server.")
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(4, 0, 0, 0, 0):  # PR_SET_DUMPABLE
        raise InstallError("Could not disable process dumps.")
    # Refuse disk-backed swap rather than guessing whether its backing device is
    # encrypted. Python immutable strings cannot promise explicit zeroization.
    if len(Path("/proc/swaps").read_text().splitlines()) != 1:
        raise InstallError("Disable swap before fetching credentials; this helper requires no active swap.")
    if libc.mlockall(1 | 2):  # MCL_CURRENT | MCL_FUTURE, retained until process exit
        raise InstallError("Memory locking failed; invoke through systemd-run with LimitMEMLOCK=infinity.")
    os.environ.clear()  # No ambient PG*, AWS keys, service files or child secrets.
    logging.disable(logging.CRITICAL)


def hostname(value):
    if len(value) > 253 or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", value):
        raise argparse.ArgumentTypeError("Expected a DNS hostname, not a URL or port.")
    if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
           for label in value.split(".")):
        raise argparse.ArgumentTypeError("Invalid DNS hostname.")
    return value.lower()


def pin(value):
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise argparse.ArgumentTypeError("Expected a lowercase SHA-256 hex pin.")
    return value


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("bundle", "release-key-file", "tuf-root-file", "backup-recipient-file", "rds-ca-file",
                 "database-secret-arn", "credential-directory"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--release-key-id", type=pin, required=True)
    parser.add_argument("--rds-ca-sha256", type=pin, required=True)
    for name in ("database-endpoint", "console-hostname", "device-hostname"):
        parser.add_argument("--" + name, type=hostname, required=True)
    parser.add_argument("--execution-root-recipient-file", action="append", required=True)
    for name in ("tls-cert-file", "tls-key-file", "tls-ca-file"):
        parser.add_argument("--" + name, help="Approved console-only TLS input; device trust stays separate")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--allow-unbound-scram", action="store_true",
                        help="Permit prefer only after an actual negative PLUS probe and successful plain SCRAM probe")
    result = parser.parse_args()
    if any((result.tls_cert_file, result.tls_key_file, result.tls_ca_file)) and not all(
            (result.tls_cert_file, result.tls_key_file, result.tls_ca_file)):
        parser.error("Bring-own console TLS requires all three --tls-*-file inputs.")
    if len(result.execution_root_recipient_file) != 3:
        parser.error("Supply exactly three distinct execution-root public recipient files.")
    if result.console_hostname == result.device_hostname:
        parser.error("Console and device hostnames must differ.")
    return result


def verify_inputs(args):
    bundle = protected(args.bundle, directory=True)
    for root, directories, files in os.walk(bundle, followlinks=False):
        for name in directories:
            protected(str(Path(root) / name), directory=True)
        for name in files:
            protected(str(Path(root) / name))
    key = read_public(args.release_key_file)
    if not key:
        raise InstallError("Empty release public key.")
    der = command(["/usr/bin/openssl", "pkey", "-pubin", "-in", args.release_key_file,
                   "-outform", "DER"], capture=True)
    if hashlib.sha256(der).hexdigest() != args.release_key_id:
        raise InstallError("Independent release key pin mismatch.")
    # Authenticate install.sh BEFORE executing it; its own checks are not an
    # authority for an unauthenticated shell script.
    manifest = read_public(str(bundle / "installer.sha256"))
    read_public(str(bundle / "installer.sha256.sig"))
    command(["/usr/bin/openssl", "pkeyutl", "-verify", "-pubin", "-inkey", args.release_key_file,
             "-rawin", "-in", str(bundle / "installer.sha256"),
             "-sigfile", str(bundle / "installer.sha256.sig")])
    entries = {}
    for line in manifest.decode("ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_./-]+)", line)
        if not match:
            raise InstallError("Malformed signed installer manifest.")
        digest, name = match.groups()
        if name in entries or name.startswith("/") or ".." in Path(name).parts:
            raise InstallError("Unsafe or duplicate signed installer asset.")
        entries[name] = digest
        p = protected(str(bundle / name))
        with p.open("rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        if actual != digest:
            raise InstallError("Signed installer asset digest mismatch.")
    if "install.sh" not in entries:
        raise InstallError("Signed installer entrypoint missing.")
    ca = read_public(args.rds_ca_file)
    if hashlib.sha256(ca).hexdigest() != args.rds_ca_sha256:
        raise InstallError("Independent RDS CA bundle pin mismatch.")
    recipients = [read_public(p).strip() for p in
                  [args.backup_recipient_file, *args.execution_root_recipient_file]]
    if read_public(args.tuf_root_file) != read_public(str(bundle / "release-root.json")):
        raise InstallError("Bundle release-update root differs from the independently authenticated root.")
    if len(set(recipients)) != 4 or any(not re.fullmatch(rb"age1[023456789acdefghjklmnpqrstuvwxyz]+", r)
                                                     for r in recipients):
        raise InstallError("Supply four distinct age X25519 public recipients, never private identities.")
    if args.tls_cert_file:
        read_public(args.tls_cert_file)
        read_public(args.tls_ca_file)
        protected(args.tls_key_file, private=True)
        protected(str(Path(args.tls_key_file).parent), directory=True, private=True)
    # Fail before any database mutation if this is not a new managed host.
    for path in ("/etc/lindm/server.json", "/etc/lindm/install-state.json",
                 "/etc/haproxy/lindm.cfg", "/etc/systemd/system/lindm-edge.service"):
        if os.path.lexists(path):
            raise InstallError("Fresh installation required; an installation or edge file already exists.")
    protected("/etc/haproxy", directory=True)
    protected("/etc/systemd/system", directory=True)
    protected(str(Path(args.credential_directory).parent), directory=True, private=True)
    os.mkdir(args.credential_directory, 0o700)  # create-only: never rotate credentials by rerunning
    protected(args.credential_directory, directory=True, private=True)
    create_file(str(Path(args.credential_directory) / "rds-ca.pem"), ca)


def master_credentials(args):
    session = boto3.Session(region_name=args.region)
    credentials = session.get_credentials()
    if credentials is None or credentials.method != "iam-role":
        raise InstallError("Secrets Manager access must use the EC2 instance role, not local credentials.")
    client = session.client("secretsmanager")
    try:
        response = client.get_secret_value(SecretId=args.database_secret_arn)
        secret = json.loads(response["SecretString"])
        if secret.get("username") != "lindm_admin" or not isinstance(secret.get("password"), str) or not secret["password"]:
            raise InstallError("RDS secret must contain the expected master username and a password.")
        return secret["username"], secret["password"]
    finally:
        client.close()


def connect(args, user, password, database, binding):
    return psycopg.connect(host=args.database_endpoint, port=5432, dbname=database,
                           user=user, password=password, sslmode="verify-full",
                           sslrootcert=str(Path(args.credential_directory) / "rds-ca.pem"),
                           sslcert="", sslkey="", passfile="/dev/null",
                           channel_binding=binding, require_auth="scram-sha-256",
                           connect_timeout=15, autocommit=True)


def binding_policy(args, user, password, database):
    try:
        with connect(args, user, password, database, "require"):
            return "require"
    except psycopg.OperationalError as error:
        # This one libpq diagnostic describes the actual SASL mechanism offer.
        # TLS, password, certificate-binding and other failures never downgrade.
        if PLUS_UNAVAILABLE not in str(error):
            raise InstallError("Verified TLS/SCRAM-PLUS probe failed; no downgrade is permitted.") from None
    with connect(args, user, password, database, "disable"):
        pass  # require_auth still enforces SCRAM, not MD5/password/trust.
    if not args.allow_unbound_scram:
        raise InstallError("PLUS was not offered and plain SCRAM succeeded. Obtain explicit policy approval, then use --allow-unbound-scram on a fresh attempt; no database changes made.")
    return "prefer"




def database_url(args, role, password, binding):
    options = {"sslmode": "verify-full", "sslrootcert": str(Path(args.credential_directory) / "rds-ca.pem"),
               "channel_binding": binding, "require_auth": "scram-sha-256"}
    return (f"postgresql://{quote(role, safe='')}:{quote(password, safe='')}@"
            f"{args.database_endpoint}:5432/lindm?{urlencode(options)}\n").encode("ascii")


def backup_clients(admin):
    server_major = int(admin.execute("SHOW server_version_num").fetchone()[0]) // 10000
    if server_major != 16:
        raise InstallError("v0.1 supports PostgreSQL 16 only; no database changes made.")
    for binary in ("/usr/bin/pg_dump", "/usr/bin/pg_restore"):
        try:
            version = command([binary, "--version"], capture=True)
        except (OSError, InstallError):
            raise InstallError("PostgreSQL 16 backup clients are required before provisioning.") from None
        match = re.search(rb"\(PostgreSQL\) (\d+)", version)
        if match is None or int(match[1]) != 16:
            raise InstallError("v0.1 requires PostgreSQL 16 pg_dump and pg_restore; no database changes made.")


def provision_database(args):
    master, master_password = master_credentials(args)
    policy = binding_policy(args, master, master_password, "postgres")
    with connect(args, master, master_password, "postgres", policy) as admin:
        backup_clients(admin)
        if admin.execute("SELECT 1 FROM pg_database WHERE datname = %s", ("lindm",)).fetchone():
            raise InstallError("Database lindm already exists; refusing destructive reprovisioning.")
        if admin.execute("SELECT 1 FROM pg_roles WHERE rolname = ANY(%s)",
                         (["lindm_runtime", "lindm_migrator"],)).fetchone():
            raise InstallError("Application roles already exist; refusing credential replacement.")
        passwords = {role: secrets.token_urlsafe(48) for role in ("lindm_runtime", "lindm_migrator")}
        for role, password in passwords.items():
            create_file(str(Path(args.credential_directory) / ("database-url" if role == "lindm_runtime" else "migration-url")),
                        database_url(args, role, password, policy))
        # Role creation is atomic. CREATE DATABASE cannot run in a transaction;
        # any later failure leaves protected recovery files, never rotates them.
        with admin.transaction():
            for role, password in passwords.items():
                # libpq generates the verifier locally; plaintext role passwords
                # never enter SQL or PostgreSQL statement/error logs.
                verifier = admin.pgconn.encrypt_password(
                    password.encode("ascii"), role.encode("ascii"), b"scram-sha-256").decode("ascii")
                admin.execute(sql.SQL("CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                                      "NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD {}").format(
                    sql.Identifier(role), sql.Literal(verifier)))
            admin.execute(sql.SQL("GRANT lindm_migrator TO {}").format(sql.Identifier(master)))
        admin.execute("CREATE DATABASE lindm OWNER lindm_migrator")
        admin.execute("REVOKE ALL ON DATABASE lindm FROM PUBLIC")
        admin.execute("GRANT CONNECT ON DATABASE lindm TO lindm_runtime")
    with connect(args, master, master_password, "lindm", policy) as admin:
        with admin.transaction():
            admin.execute("ALTER SCHEMA public OWNER TO lindm_migrator")
            admin.execute("SET LOCAL ROLE lindm_migrator")
            admin.execute("REVOKE ALL ON SCHEMA public FROM PUBLIC")
            admin.execute("GRANT USAGE ON SCHEMA public TO lindm_runtime")
            admin.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO lindm_runtime")
            admin.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO lindm_runtime")
            admin.execute("ALTER DEFAULT PRIVILEGES FOR ROLE lindm_migrator IN SCHEMA public "
                          "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO lindm_runtime")
            admin.execute("ALTER DEFAULT PRIVILEGES FOR ROLE lindm_migrator IN SCHEMA public "
                          "GRANT USAGE, SELECT ON SEQUENCES TO lindm_runtime")
    with connect(args, master, master_password, "postgres", policy) as admin:
        admin.execute(sql.SQL("REVOKE lindm_migrator FROM {}").format(sql.Identifier(master)))
    # Probe the actual login roles too; master success alone is not evidence for
    # the application authentication path. No passwords or raw errors are printed.
    for role, password in passwords.items():
        actual = binding_policy(args, role, password, "lindm")
        if actual != policy:
            raise InstallError("Authentication policy changed during provisioning; installation stopped.")
    return policy


def install_bundle(args):
    directory = Path(args.credential_directory)
    flags = ["/bin/sh", str(Path(args.bundle) / "install.sh"),
             "--release-key-file", args.release_key_file, "--release-key-id", args.release_key_id,
             "--backup-recipient-file", args.backup_recipient_file,
             "--origin", "https://" + args.console_hostname + ":443",
             "--device-origin", "https://" + args.device_hostname + ":443",
             "--admin-port", "18444", "--device-port", "18445",
             "--database-url-file", str(directory / "database-url"),
             "--migration-url-file", str(directory / "migration-url"),
             "--setup-code-file", str(directory / "setup-code")]
    for recipient in args.execution_root_recipient_file:
        flags.extend(["--execution-root-recipient-file", recipient])
    if args.tls_cert_file:
        flags.extend(["--tls-cert-file", args.tls_cert_file, "--tls-key-file", args.tls_key_file,
                      "--tls-ca-file", args.tls_ca_file])
    command(flags, diagnostic_path=directory / "installer-diagnostic.private")


def install_edge(args):
    # TCP only: the native listener terminates TLS and validates device mTLS.
    configuration = f"""global
    user haproxy
    group haproxy
    maxconn 4096

defaults
    mode tcp
    timeout connect 10s
    timeout client 5m
    timeout server 5m

frontend lindm_tls
    bind 0.0.0.0:443
    tcp-request inspect-delay 5s
    acl client_hello req.ssl_hello_type 1
    acl console_sni req.ssl_sni -i {args.console_hostname}
    acl device_sni req.ssl_sni -i {args.device_hostname}
    tcp-request content reject if client_hello !console_sni !device_sni
    tcp-request content accept if client_hello
    use_backend lindm_console if console_sni
    use_backend lindm_device if device_sni

backend lindm_console
    server native 127.0.0.1:18444

backend lindm_device
    server native 127.0.0.1:18445
"""
    unit = """[Unit]
Description=Lindm TLS SNI TCP passthrough
After=network-online.target lindmd.service
Wants=network-online.target
[Service]
Type=notify
ExecStart=/usr/sbin/haproxy -Ws -f /etc/haproxy/lindm.cfg -p /run/lindm-edge.pid
ExecReload=/bin/kill -USR2 $MAINPID
Restart=on-failure
LimitCORE=0
MemorySwapMax=0
[Install]
WantedBy=multi-user.target
"""
    # These public configuration locations are root-protected but not private;
    # write directly with exclusive creation rather than replacing distro files.
    for path, content in (("/etc/haproxy/lindm.cfg", configuration),
                          ("/etc/systemd/system/lindm-edge.service", unit)):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    command(["/usr/bin/systemctl", "daemon-reload"])
    command(["/usr/bin/systemctl", "enable", "--now", "lindm-edge.service"])


def main():
    args = arguments()
    secure_memory()
    verify_inputs(args)
    policy = provision_database(args)
    install_bundle(args)
    install_edge(args)
    print("Installation commands completed; perform the independent trust and acceptance steps in docs/deploy-aws.md.")
    print("Database channel binding policy: " + policy)
    print("Setup code is in the root-only credential directory; never print it into SSM output.")


if __name__ == "__main__":
    try:
        main()
    except InstallError as error:
        print("Installation stopped: " + str(error), file=sys.stderr)
        sys.exit(1)
    except (Exception, KeyboardInterrupt):
        # SDK/libpq exceptions may contain connection strings or server SQL.
        # Never emit exception text, tracebacks, subprocess output, or locals.
        print("Installation stopped; diagnostic details withheld to protect credentials. "
              "Retain root-only files and inspect host/RDS state privately before recovery.", file=sys.stderr)
        sys.exit(1)
