# Install lindm

Use a dedicated Ubuntu 24.04 x86 server, or RHEL 9 for the preview described below. Give the server a stable DNS name.
An IP-address URL cannot be a WebAuthn relying-party ID. Use the DNS name for first-owner password and passkey setup.
The browser and managed devices must reach its HTTPS listeners.
For RHEL, retain access to the configured entitled Red Hat repositories.

## Before you start

Obtain the signed release directory and the release verification key through your
trusted customer channel. Verify it against that independently pinned key before
you run its installer. A key inside the bundle does not establish trust.
Never use a development signing key for a customer installation.

Prepare an **age public recipient key** for backups. Keep its private identity
outside the server. Test that identity on the operator's recovery computer.
Retain the signed bundle, verification key and backup identity for recovery.

## Install the server

From the authenticated release directory, run:

```sh
sudo ./install.sh
```

Supply the stable HTTPS origin, independently trusted release-key reference and
backup recipient when the installer asks. Do not enter credentials into a shared
terminal recording.
If you omit custodian recipient keys, choose a recovery-export passphrase when
prompted. Keep the passphrase outside the server.

The installer installs native packages and hardened services. It configures local
PostgreSQL, separate database roles, TLS, server keys and scheduled encrypted
backups. It runs explicit migrations and checks readiness before printing the
console URL and a one-time setup code. Keep the code private.
Connected installation uses the server's configured, signed distribution
repositories. For RHEL, keep its entitlement available.
RHEL 9 explicitly selects the distribution's PostgreSQL 16 stream and checks its
server and backup clients before provisioning. Conflicting PostgreSQL modules,
older server/client packages and unrelated clusters are refused without reset or
migration: use a fresh supported turnkey host.
The root-only file `/var/lib/lindmd-operations/setup/code` also holds the code.
Database URLs and the integrations encryption key stay root-owned and private.
Native services receive temporary systemd credentials, not ownership of those files.

The console has its own browser-compatible certificate. For a private CA, import
`/etc/lindm/console-ca.crt` on the administrator's computer and check the fingerprint
printed by the installer. Do not import the device CA instead. Publicly trusted
console certificates do not need a custom CA import.

Server status marks an absent private CA for the console as inactive.
This does not mean that the console lacks HTTPS.

**v0.1.0 supports PostgreSQL 16 only**, for local and existing databases.
Older and newer server versions are refused before migrations. To use an existing
PostgreSQL 16 database, provide protected runtime and migration URL files. Each
connection must verify the database certificate. See the
[installation runbook](security-and-operations.md#native-single-host-installation)
for the actual options, required grants and certificate choices.

For an Ubuntu 24.04 server on AWS with private RDS PostgreSQL, use the
[AWS deployment runbook](deploy-aws.md). It covers SSM access, external-database
credentials, browser trust and cleanup.

For an Ubuntu 24.04 air gap, use the bundle's authenticated Ubuntu offline add-on
and run `sudo ./install.sh --airgap`. A missing add-on stops installation; it never
downloads missing dependencies from the Internet. Keep DNS, time and certificate
trust available inside the site.

The server install is supported on Ubuntu 24.04, including the AWS deployment.
RHEL 9 server install is a preview in this release: install, setup, enrollment and
device management work; vulnerability findings for RHEL devices on a fresh install
and backup/restore on a RHEL server are still being verified.

**v0.1.0 RHEL 9 is connected-only.** `--airgap` stops before mutation with
“RHEL offline installation is not available in this release”. An entitled offline
repository or the older generic PostgreSQL snapshot does not bypass this limit.

## Create the first owner

1. Trust the installer-generated CA through your approved browser trust process,
   or use your organization's certificate.
2. Open the single console URL. Enter the one-time setup code.
3. Set your account name and password. Register a user-verifying passkey.
4. Confirm the dashboard opens. Check the agent repository in **Settings**.
5. If **Server status** shows a recovery-key task, move the encrypted export
   off-host. Confirm the task with your password and passkey.
6. Choose **Enroll**. Copy the command to a second Linux device and run it with
   administrative privileges. Confirm that the device appears as **Enrolled**.

The setup code cannot replace a password or passkey after setup completes. If its
expiry interrupts setup, use the protected setup-code procedure in the runbook.
Never disable TLS or package verification to complete enrollment.

## Wait for the first vulnerability assessment

Connected turnkey installations automatically select real vendor advisory exports
after a supported device sends its managed package inventory. There is no feed
configuration step. The server selects only the enrolled product, release,
architecture and corroborated servicing stream; it does not download every
distribution's archive before enrollment.

The first download may be large. Its elapsed time depends on the actual vendor
export, link and parsing work; measure the observed start-to-evaluation duration
instead of assuming a fixed completion time. A live refresh reports its real start
and publication lease, not an estimated percentage. Downloading or waiting is not
an assessment: findings stay unknown until verified publication and the device's
background evaluation complete. Failed, stale and partial coverage stay visible.
Later attempts use the durable per-source schedule, six hours by default.

One Ubuntu 24.04 x86 laboratory run on 15 October 2026 took about 6 minutes
19 seconds from starting the installer to observing qualifying findings for the
newly enrolled device. The observed first refresh start to its stored evaluation
took 3 minutes 17 seconds. The first measurement includes installation, owner
setup, enrollment and inventory collection. These are measurements, not completion
guarantees. The full install, upgrade and recovery result is recorded in the
[deployment evidence](verification.md#control-plane-deployment-matrix).

Air-gap installs do not enable network refresh. Explicit advisory policy, including
disabled refresh and custom sources, survives managed upgrades. New installations
record their original air-gap mode; a missing advisory section on a known connected
installation receives the same automatic defaults on upgrade. Older journals that
did not record the mode keep their absent advisory policy without enabling egress
or adding a new upgrade refusal.

## Set up integrations and reports

Native installation enables integrations and reports. The installer creates the
encryption key. You do not need to make or configure a key.
After setup, add a webhook or TLS syslog destination in **Integrations**.
Configure report schedules in the console.

Encrypted backups include the key. Restore uses the original key with the
restored database. Never replace the key to clear a setup warning.
Managed upgrades create a key only when integrations have no configured key.

## Keep the service recoverable

Check **Server status** after installation and each upgrade. Resolve database,
certificate, backup or repository warnings before a maintenance window.
Import the customer's signed release feed to learn about updates offline.
Apply the authenticated next bundle through its installer, not by replacing the
server executable. The upgrade requires preflight checks and an encrypted backup.

Native backups use the root-only migration configuration at
`/etc/lindm/migrate/server.json` to read the complete database. Backup checks that
the migration and runtime credentials name the same database and application
schema before it runs `pg_dump`. Keep the migration configuration and credential
root-only. Do not grant runtime access to the migration ledger's sequence to
repair a failed backup.

If a first installation is interrupted, correct the reported problem and rerun
the same authenticated bundle with the same origins, trust keys, recipients and
database/TLS inputs. The protected `/etc/lindm/install-state.json` journal is
written before package installation and provisioning. A retry retains committed
deployment keys, custody exports, credentials and database state; do not remove
them to make the installer run again. Only incomplete, unpublished bootstrap
identity generation is discarded before retrying. A different bundle or changed
provisioning inputs cannot take over an unfinished installation.

An upgrade records its attempted and native-installed release separately from
the last release that passed readiness. If a newer package fails readiness, use
the previous release's authenticated signed bundle with `--rollback` only when
the installer admits its schema compatibility. The native package version, not
the last-ready marker, determines whether this is a rollback. Schema preflight
and an encrypted backup remain mandatory; rollback never runs schema Down.

Version **v0.1.0** starts the browser-compatible managed-upgrade baseline.
Pre-turnkey installations and earlier shared-TLS laboratory installs need a fresh
server and device re-enrollment. The installer refuses them before upgrade changes:
"This installation predates the browser-compatible console certificate. Install
fresh and re-enroll devices." Keep their data and keys until you approve retention.

Run the documented restore drill before relying on backups. A stale restore stays
fenced until its signed recovery checkpoint reconciles security state.
Removal retains database data, keys and backups. Erasing retained data requires a
separate retention decision.

See the [operations runbooks](security-and-operations.md) and
[qualification evidence](verification.md). A successful readiness check does not
prove browser setup, device management or recovery.
