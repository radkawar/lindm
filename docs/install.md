# Install lindm

Use a dedicated Ubuntu 24.04 or RHEL 9 x86 server. Give the server a stable DNS name.
The browser and managed devices must reach its HTTPS listeners.
For RHEL, retain the required Red Hat subscription or an entitled offline repository.

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
The root-only file `/var/lib/lindmd-operations/setup/code` also holds the code.
Database URL files stay root-owned and private. Native services receive temporary
systemd credentials, not ownership of those files.

To use an existing PostgreSQL database, provide protected runtime and migration
URL files. Each connection must verify the database certificate. See the
[installation runbook](security-and-operations.md#native-single-host-installation)
for the actual options, required grants and certificate choices.

For an air gap, use the bundle's authenticated offline add-on for your server
platform and run `sudo ./install.sh --airgap`. A missing platform add-on stops
installation; it never downloads missing dependencies from the Internet.
Keep DNS, time and certificate trust available inside the site.

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

## Set up integrations and reports

The turnkey installer does not enable integrations by default. **Integrations**
shows **Integrations are not set up** until the server administrator:

1. Creates a cryptographically random encryption key containing exactly 32 raw
   bytes (not hexadecimal or base64), in a protected file readable by `lindmd`.
2. Sets `integrations.encryptionKeyFile` to that file's path in
   `/etc/lindm/server.json`.
3. Backs up the key securely with the deployment's recovery material, then
   restarts `lindmd`.

This enables destinations, delivery history and signed reports together. Never
replace a deployed key to resolve a setup problem: existing destination
credentials depend on it. After setup, add a webhook or TLS syslog destination
and configure report schedules in the console.

## Keep the service recoverable

Check **Server status** after installation and each upgrade. Resolve database,
certificate, backup or repository warnings before a maintenance window.
Import the customer's signed release feed to learn about updates offline.
Apply the authenticated next bundle through its installer, not by replacing the
server executable. The upgrade requires preflight checks and an encrypted backup.

The first turnkey release starts managed upgrades. Pre-turnkey manual and lab
installations need a fresh server and device re-enrollment. Keep their data and
keys until you approve retention.

Run the documented restore drill before relying on backups. A stale restore stays
fenced until its signed recovery checkpoint reconciles security state.
Removal retains database data, keys and backups. Erasing retained data requires a
separate retention decision.

See the [operations runbooks](security-and-operations.md) and
[qualification evidence](verification.md). A successful readiness check does not
prove browser setup, device management or recovery.
