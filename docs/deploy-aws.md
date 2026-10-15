# Install on AWS with an external RDS database

Use this runbook for a fresh server with an external RDS database. A completed
installation is not browser, enrollment or restore proof.
Record actual results for every phase. Read [installation](install.md),
[self-built releases](self-built-releases.md) and the
[native operations runbook](security-and-operations.md#native-single-host-installation).

## Scope and trust boundaries

Use a fresh Canonical Ubuntu 24.04 **amd64** server. This runbook uses `us-east-1`.
Terraform creates the network, EC2 instance, two public HTTPS names and a private
RDS PostgreSQL instance. An optional second EC2 instance is the managed device.
The two EIPs give the console and device separate origins on port 443.
The server accepts HTTPS only; use Systems Manager (SSM), not inbound SSH.
If you use this helper on a separately provisioned SSH-accessible host, apply the
same root custody and private-terminal rules. The supplied Terraform disables SSH.

The EC2 instance role has SSM access and `secretsmanager:GetSecretValue` for the
exact RDS-managed master-secret ARN. The helper rejects other AWS credential
sources. Terraform does not generate, receive or output database passwords.
The role can also read exactly the `release.tar` object in the private transfer
bucket. This permits authenticated SSM-driven transfer without a bearer URL.
The role can read and write exactly `backup.age` and `security-backup.age` in that
bucket. Upload only the encrypted archives made by `lindmd backup`. The role
cannot list the bucket, delete objects or write the release.

The server blocks access to instance metadata from non-root processes. This keeps
the unprivileged `lindmd` service from using the master-secret permission through
the instance role. The `lindm-imds-guard.service` rule starts before `lindmd`.
Root processes, including SSM and the installer helper, can use IMDSv2.
The IPv6 metadata endpoint is disabled. Do not remove this rule while the role
can read the master secret.
Do not use `aws secretsmanager get-secret-value` in a terminal or SSM command.
Do not put credentials in Terraform variables, state, user data or outputs.
Protect Terraform state and plan files even though no master password is included.

Both EC2 root volumes and RDS storage are encrypted by AWS. EBS encryption is
below the guest operating system. The enrolled device can still report that its
Linux root filesystem has no LUKS encryption. Do not interpret AWS storage
encryption as an operating-system recovery key or a managed LUKS policy.

This is a disposable, single-server deployment, not a highly available service.
RDS is private and not Multi-AZ. The supplied configuration has a short backup
retention period and **skips the final snapshot and deletes automated backups on
destroy**. Change retention deliberately before keeping important data.
Resources are tagged `project=lindm` and `purpose=ci-proof`.
Terraform also tags the AWS-created VPC defaults and instance and RDS network
interfaces. RDS copies the database tags to its managed master secret. Verify the
secret's metadata tags without retrieving its password.

Use a deployment name with 3 to 28 lowercase letters, digits or hyphens, starting
with a letter. The transfer bucket adds `-release-` and a unique suffix. Its
[provider bucket-prefix limit](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket)
is 37 characters.
Do not use consecutive hyphens, end with a hyphen, or start with `sg-`. These
restrictions also meet the
[RDS identifier](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateDBInstance.html)
and [EC2 security-group name](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateSecurityGroup.html)
rules.

HAProxy runs in TCP mode on port 443. It routes the console SNI name to
`127.0.0.1:18444` and the device SNI name to `127.0.0.1:18445`.
It does not terminate TLS, add PROXY headers or authenticate client certificates.
The native device listener still validates mTLS. Unknown SNI names are rejected.
Do not replace this with an HTTP reverse proxy or expose ports 18444/18445 in the
security group. DNS delivery alone is not a certificate trust decision.

## 1. Build and retain the signed release off-server

Use your approved signing workstation and the pinned source revision/toolchains.
Follow [self-built releases](self-built-releases.md) for signing custody, memory
and swap requirements. In that checkout, as your normal user:

```sh
make bootstrap
make release-keys
make release
go run ./cmd/release verify --directory artifacts/release --keys release-keys
```

Keep `release-keys/`, `custody.age`, unlock secrets, signing keys and backup private
identities **off EC2**. Do not archive or upload that directory. Retain the exact
signed release directory and its version for recovery.

Prepare these public installation inputs through your authenticated custody channel:

- The release-attestation public key and its independently approved lowercase
  SHA-256 of SPKI DER (`--release-key-file`, `--release-key-id`).
- The independently approved signed release-update root (`--tuf-root-file`).
  It must match the release's `release-root.json` byte for byte. A root fetched
  from the bundle alone does not establish trust.
- One backup age X25519 public recipient. Retain and test its private identity on
  the recovery workstation.
- **Three distinct** execution-custodian age X25519 public recipients, one file
  per custodian. They must also differ from the backup recipient. Keep their
  private identities with the custodians, not on EC2. Three supplied recipients
  avoid the installer's generated-identity passphrase prompt on SSM. One or two
  recipients do not avoid that prompt. Three keys do not prove three humans.
- The helper `deploy/aws/install-external-db.py` from the independently approved
  source revision. Authenticate its SHA-256 through the operator channel before
  running it; the signed release bundle does not automatically sign this helper.

The helper authenticates the release-key pin, signed installer asset manifest and
asset hashes **before executing `install.sh`**. The bundle installer then verifies
its complete release, package and repository payload. Neither step makes an
in-bundle public key an independent trust anchor.

## 2. Apply Terraform without secrets

Authenticate your AWS operator session. Select an approved Canonical Ubuntu 24.04
amd64 AMI in `us-east-1`; authenticate its publisher and image ID independently.
The provider checks `allowed_account_id` before managing any resource. The default
is deliberate. Set it to your intended AWS account.
Review available RDS engine versions, parameter family and instance class in that
region; they must agree. Set `ami_id`, `allowed_account_id` and any nonsecret size
or version overrides in a protected operator `.tfvars` file.

Use Terraform 1.11 or newer and AWS provider major version 6. The checked-in lock
file pins the provider used by this module.

From `deploy/aws/terraform`:

```sh
terraform init
terraform plan -var-file=/operator/aws.tfvars -out=/operator/aws.plan
terraform apply /operator/aws.plan
terraform output -json
```

Retain these public outputs: `server_instance_id`, `device_instance_id`,
`console_hostname`, `device_hostname`, `database_endpoint`,
`database_secret_arn`, `region` and `release_transfer_bucket`. The database endpoint is a hostname, not an
IP address or an HTTPS URL. The helper uses PostgreSQL port 5432, master user
`lindm_admin`, initial database `postgres`, and creates application database `lindm`.
Do not change the endpoint to an IP; `verify-full` verifies the RDS hostname.

Open an SSM session to `server_instance_id`. Wait for `cloud-init status --wait`
to complete. Cloud-init installs `python3-psycopg`, `python3-boto3`, HAProxy, curl
and CA certificates from the signed Ubuntu repositories. The system libpq must
support `require_auth` (PostgreSQL 16 or newer). Do not install an old client or
remove the option to bypass an error. OpenSSL must be installed on the server.
The helper and native installer require cgroup v2 and locked secret memory.
Disable active swap before installation. Do not enable swap during the operation.

### Match PostgreSQL backup clients to RDS

The native backup and restore commands execute `/usr/bin/pg_dump` and
`/usr/bin/pg_restore`. Ubuntu 24.04's vendor PostgreSQL 16 client cannot dump an
RDS 18 database. Install an approved PostgreSQL 18 client before invoking the
helper when using the Terraform RDS 18 defaults. Keep the vendor dependency used
by the native installer; Debian's `pg_wrapper` selects the newest installed client.
If selecting another RDS major, approve matching or newer clients for that major.
The helper compares both actual client versions with RDS `server_version_num`
before creating roles or the application database. Never bypass this gate.

Use the authenticated [PostgreSQL Ubuntu repository](https://www.postgresql.org/download/linux/ubuntu/)
if your approved Ubuntu repositories do not carry the required client.
On the server, download the public repository key over verified HTTPS into a
root-protected file. Inspect its full primary fingerprint and compare it with your
independently approved PGDG signing-key fingerprint before adding repository trust.
The key URL is distribution, not the independent approval:

```sh
sudo curl --fail --proto '=https' --tlsv1.2 \
  --output /root/pgdg.asc https://www.postgresql.org/media/keys/ACCC4CF8.asc
sudo gpg --show-keys --with-fingerprint /root/pgdg.asc
# Stop unless the complete fingerprint matches the approved custody record.
sudo install -d -o root -g root -m 0755 /etc/apt/keyrings
sudo install -o root -g root -m 0644 /root/pgdg.asc /etc/apt/keyrings/pgdg.asc
sudo tee /etc/apt/sources.list.d/pgdg.sources >/dev/null <<'EOF'
Types: deb
URIs: https://apt.postgresql.org/pub/repos/apt
Suites: noble-pgdg
Components: main
Architectures: amd64
Signed-By: /etc/apt/keyrings/pgdg.asc
EOF
sudo apt-get update
sudo install -d -o root -g root -m 0755 /etc/postgresql-common
sudo sh -c 'set -C; printf "create_main_cluster = false\n" > /etc/postgresql-common/createcluster.conf'
sudo apt-get -o Dpkg::Options::=--force-confold install postgresql-client-18
```

Do not use `trusted=yes`, a global keyring, or disabled APT signature checks.
Only public repository material is transferred; no database credentials enter
these commands. The helper's live version preflight is still required.
The create-only cluster-policy command stops if a policy already exists. Do not
overwrite an existing operator file. The installer reads the root-protected
standalone disabled setting before package changes; no preinstalled `pg_conftool`
or manual `postgresql-common` installation is required. Includes, duplicate
creation switches and unsupported syntax are refused.
This preseed prevents a vendor default cluster; the external RDS database remains
the only application database.

## 3. Authenticate the RDS CA and transfer public artifacts

On the operator workstation, obtain the current AWS RDS CA bundle using your
approved authenticated AWS distribution channel. AWS documents the global bundle
at <https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem> and the
[RDS certificate trust procedure](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html).
Use HTTPS verification. Confirm the CA selection and record the bundle SHA-256
through an independent operator approval channel. Supplying a checksum downloaded
alongside an unauthenticated file is not independent authentication.
Use the database's `CACertificateIdentifier` from the authenticated RDS API and
the matching `describe-certificates` metadata to confirm that the approved bundle
contains the selected AWS CA. Keep that check and the approved bundle SHA-256
with the deployment evidence. If the bundle changes, approve the new bytes
independently before retrying; do not accept a new hash just to clear a failure.
The helper requires this pin with `--rds-ca-sha256`; it never downloads or trusts
a replacement CA and never uses `sslmode=require`, `no-verify`, or insecure curl.

Transfer only the signed release directory, authenticated helper and **public**
trust files to the server. Terraform's `release_transfer_bucket` is private,
encrypted and blocks public access; use short-lived presigned GET URLs for the
exact bundle object. Transfer public trust files and their independent pins
separately over SSM. Archive only `artifacts/release/`, not your source checkout
or signing directory. Issue each URL with a short expiry through the protected SSM
session; it is a temporary bearer capability. Do not paste it into tickets,
shared transcripts or long-lived SSM Run Command documents. Avoid recorded
sessions when handling temporary transfer capabilities.

For the SSM instance-role transfer, upload the signed archive as `release.tar`
in `release_transfer_bucket`. In the root-only server session, use boto3's
`download_file` with the instance role to retrieve that exact object. The role
has no bucket-list permission and cannot write the release. Its other object
permissions are limited to the two encrypted backup filenames. Public trust files
and independent pins still come through the separate authenticated operator
channel.

Use a root-only transfer directory. If using curl, keep each URL in a temporary
root-owned mode 0600 curl configuration file, not argv or environment:

```sh
sudo install -d -o root -g root -m 0700 /root/lindm-transfer
# In the private root session, create curl.conf with: url = "PRESIGNED_GET_URL"
# Add: output = "/root/lindm-transfer/release.tar.gz"
sudo curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
  --config /root/lindm-transfer/curl.conf
sudo rm -- /root/lindm-transfer/curl.conf
```

Repeat for the authenticated helper and public trust files, or transfer those
public bytes through your approved SSM file-transfer process. Authenticate each
file against the independently retained pins before use. Extract your own
operator-created release archive as root into `/root/lindm-transfer/release` with
`tar --no-same-owner -xf ARCHIVE -C /root/lindm-transfer/release`. Do not restore
the workstation's UID/GID from archive metadata. Use no symlinks, hard links or
special files. The helper and installer reject them.
All input files and their ancestors must be root:root and not group/world
writable. The transfer directory must remain mode 0700; public files may use 0600.
Do not transfer any database URL, master password, private age identity, signing
key or custody passphrase. Delete uploaded S3 objects and expired capabilities
according to your retention policy after the transfer.

## 4. Invoke the root helper

In the protected root session set the following **public** shell variables from
Terraform outputs and your independent custody record:
`DATABASE_ENDPOINT`, `DATABASE_SECRET_ARN`, `CONSOLE_HOSTNAME`, `DEVICE_HOSTNAME`,
`RELEASE_KEY_ID`, and `RDS_CA_SHA256`. They are not password variables.
Use the actual absolute paths of the transferred files. The example names below
are operator-selected staging names, not promised release-key export filenames.
`/root/lindm-aws` must not exist before the first attempt.

```sh
sudo systemd-run --unit=lindm-aws-install --wait --collect \
  --property=LimitMEMLOCK=infinity --property=LimitCORE=0 \
  --property=MemorySwapMax=0 \
  /usr/bin/python3 /root/lindm-transfer/install-external-db.py \
  --region us-east-1 \
  --database-endpoint "$DATABASE_ENDPOINT" \
  --database-secret-arn "$DATABASE_SECRET_ARN" \
  --rds-ca-file /root/lindm-transfer/global-bundle.pem \
  --rds-ca-sha256 "$RDS_CA_SHA256" \
  --console-hostname "$CONSOLE_HOSTNAME" \
  --device-hostname "$DEVICE_HOSTNAME" \
  --bundle /root/lindm-transfer/release \
  --release-key-file /root/lindm-transfer/attestation.pub \
  --release-key-id "$RELEASE_KEY_ID" \
  --tuf-root-file /root/lindm-transfer/approved-release-root.json \
  --backup-recipient-file /root/lindm-transfer/backup-recipient.txt \
  --execution-root-recipient-file /root/lindm-transfer/custodian-1.txt \
  --execution-root-recipient-file /root/lindm-transfer/custodian-2.txt \
  --execution-root-recipient-file /root/lindm-transfer/custodian-3.txt \
  --credential-directory /root/lindm-aws
```

This command is suitable for a root SSM Run Command after transfer: all arguments
are public configuration or protected file paths. Never append a password, URL
credential, passphrase or private key. Do not run with shell tracing.

The helper fetches the RDS-managed master secret in memory using the instance
role. It disables core dumps, locks current/future memory and refuses active swap.
It does not print, persist or pass the master password to a subprocess. Raw
SDK/libpq/installer diagnostics are withheld because they can contain secrets.

Before any database mutation it makes a real `channel_binding=require` connection
with `sslmode=verify-full` and `require_auth=scram-sha-256`. Success keeps `require`.
Only libpq's specific “server did not offer an authentication method that supports
channel binding” response is accepted as a negative PLUS result. The helper then
requires a successful actual plain-SCRAM connection, still with verified TLS and
`require_auth=scram-sha-256`. Certificate errors, bad credentials and other failures
never authorize fallback.

If and only if that negative/success pair is observed, the helper stops before
creating roles and asks for explicit approval. Your security policy may authorize
a new attempt with `--allow-unbound-scram`. Remove **only** the first attempt's
CA-only credential directory after privately confirming that it contains neither
URL file nor setup code, then invoke the same command with that extra flag.
The helper probes again; the flag alone cannot force a downgrade. Approved URLs
use `channel_binding=prefer`, never `disable`, and retain the SCRAM restriction.
The native application reports the downgrade as **Needs attention**; do not label
it a fully bound connection or suppress its warning. Prefer a PLUS-capable endpoint.

Provisioning creates distinct `lindm_migrator` and `lindm_runtime` logins with random
passwords. Both lack superuser, CREATEDB, CREATEROLE, replication and BYPASSRLS.
The migrator owns `lindm` and its public schema. Runtime has CONNECT, schema USAGE,
table DML and sequence USAGE/SELECT; it has no ownership, schema CREATE or database
TEMP/CREATE privileges. Migrator default privileges grant future table/sequence
access. Password SQL uses SCRAM verifiers and safe SQL composition, not plaintext
password strings. Temporary master membership in the migrator is revoked after
successful provisioning. Existing roles or database are never taken over.

The helper creates `database-url`, `migration-url` and a pinned `rds-ca.pem` under
`/root/lindm-aws`; URL files are root:root 0600, and creation is exclusive.
It invokes the bundle's `install.sh` with both protected URL-file flags, both
explicit `https://HOST:443` origins, listener ports 18444/18445, the public trust
flags, all three execution recipients and create-only `--setup-code-file`.
No private-terminal passphrase is needed. The installer keeps its persistent URL
copies root-owned at `/etc/lindm/database-url` and
`/etc/lindm/migrate/database-url`; systemd `LoadCredential=` supplies ephemeral
credentials to the distinct runtime and migrator service identities.
Finally the helper starts `lindm-edge.service` with create-only HAProxy configuration
at `/etc/haproxy/lindm.cfg`. It does not replace the distro HAProxy configuration.

### Optional: an owned domain and public console TLS

The default generated private CA is intentional. You cannot authorize public ACME
issuance for Amazon-owned EC2 public DNS names. If you control your own domain,
choose separate console/device names before first installation and point them at
the two Terraform EIPs. Supply those owned names to the helper instead of the
default hostname outputs. Origins are deployment bindings, not a later DNS alias.

Use your approved PKI or the maintained distro Certbot client with an authorized
ACME account. Generate the TLS private key on the server under root-only custody;
transfer only a CSR outward and the public certificate chain/approved root back.
Use your DNS provider's approved DNS-01 custody flow or the documented HTTP-01
procedure in the [TLS runbook](security-and-operations.md#native-single-host-installation);
HTTP-01 needs an explicitly authorized temporary port-80 ingress rule, which this
Terraform does not create. Do not place DNS API credentials in Terraform or SSM
command arguments. Before invoking the helper, provide a chain valid for the
console hostname, its root-owned 0600 non-symlink private-key file and an independently
approved root file. Add all three helper flags: `--tls-cert-file /ABS/CHAIN`,
`--tls-key-file /ABS/KEY`, and `--tls-ca-file /ABS/ROOT`. These are passed to the
native installer together for console TLS only. The device CA and device server
leaf remain independently generated. The console CA never enters the device TLS
trust pool. Private-key transfer through S3 is not part of this
procedure. Retain custody and arrange approved renewal; the helper does not
contact ACME, renew certificates, or modify trust after installation.

Do not rerun this fresh-install helper to upgrade or rotate a password.
A failure may leave application roles, an empty or partially configured database,
protected URL files, or native installation state. Retain them and inspect state
privately. Do not delete credentials, reset roles, or claim a clean rollback from
an exit code. After a partial mutation use the approved repair/recovery procedure
or deliberately reprovision a disposable deployment. Managed upgrades use the
[native signed-update procedure](security-and-operations.md#support-private-offline-updates-and-removal).

## 5. Establish workstation and device trust independently

The generated console CA is **not** already trusted by your browser.
Copy the public `/etc/lindm/console-ca.crt` and its independently authenticated
SHA-256 to your operator workstation. Use your organization's approved trust
import process. Do not click through certificate warnings. Check the exact console
hostname and open `https://CONSOLE_HOSTNAME` only after trust is established.
Before declaring the console live, load its setup page in stock Chromium with the
authenticated CA imported. Use no certificate-error bypass or TLS algorithm
override. The maintained deployment browser harness has a separate `tls` phase
for this check; it requires the real setup control to be visible. Curl and OpenSSL
can accept certificate algorithms that a browser rejects, so their success alone
does not prove browser compatibility.

The console CA is separate from `/etc/lindm/transport-ca.crt`, which is the
device-only CA. Do not import the device CA as the console's trust anchor or reuse
the console trust pool for device connections. The signed enrollment bootstrap
authenticates the two origin-specific authorities separately.

Retrieve `/root/lindm-aws/setup-code` over an approved private channel with recording
and logging disabled. Never `cat` it into SSM Run Command output or a shared terminal.
The canonical code also remains under `/var/lib/lindmd-operations/setup/code`.
Complete owner setup with password and a user-verifying passkey.

Transfer the three encrypted execution-root artifacts and sealed PKI artifact
from `/etc/lindm/offline` to their assigned custodians. Authenticate ciphertext
hashes and retain them off-host; the first supplied custodian protects generated
CA custody. Use `lindmd custody-status -config /etc/lindm/server.json` and the
[operations custody procedure](security-and-operations.md#native-single-host-installation).
A successful install does not prove those copies are recoverable.

For the optional device, open SSM on `device_instance_id`. Confirm the console's
agent repository is Ready. Issue its one-use enrollment command privately.
Provide the package-signing fingerprint, execution-root SHA-256 and private
transport CA trust through the independent device-admin channel before running it.
Do not put the bearer enrollment command in SSM Run Command logs. Use a private,
nonrecorded enrollment session and the documented protected grant file procedure.
Confirm the actual device is **Enrolled** in the console and perform an approved
managed action. A running systemd service or readiness response is not that proof.

### Wait for real vendor advisories

Connected native installations select real vendor advisory exports after a
supported device sends its managed package inventory. There is no separate feed
configuration step. Use the console to request a fresh inventory and wait for
that real device action to complete.

Open **Server status** and inspect the first-download state. Downloading or waiting
does not mean the device has been assessed. Wait for verified source publication
and the device's background evaluation. The first transfer and parsing work can
take time; record the observed duration, not an estimated percentage.
Later refresh attempts use the durable source schedule, six hours by default.

Inspect source status, actual package versions and findings together. Record real
vendor/package/version matches and any missing, stale or partial coverage.
A fresh source is not necessarily complete coverage. Never fabricate a finding
or treat an unchecked device as clean.

Do not edit or rebind the canonical configuration to force a result. Keep
credentials, keys and recovery custody unchanged. For air-gap or explicit
operator policy, follow [the installation policy](install.md#wait-for-the-first-vulnerability-assessment)
and [advisory feed operations](engineering.md#advisory-feed-operations).

## 6. Backup, restore and cleanup

Create an encrypted application backup and retain an immutable off-host copy:

```sh
sudo lindmd backup -config /etc/lindm/server.json \
  -recipient-file /etc/lindm/backup-recipient -output-dir /var/backups/lindm
```

The native backup uses the protected migration credential for a complete dump.
Keep that credential root-only. Do not give the runtime role ownership or access
to the protected migration ledger to make `pg_dump` succeed.

Keep the backup private key and execution-custodian identities off-host. Keep the
original integrations encryption key inside its authenticated encrypted backup;
never replace it to clear an error. RDS snapshots alone do not include server
keys, custody ciphertexts, integrations encryption key or application recovery
approvals. They are not a substitute for the application backup.

The transfer bucket permits two encrypted recovery objects: `backup.age` and
`security-backup.age`. From the root session, use the instance-role S3 client to
upload the normal archive as `backup.age`. After fencing, upload the current
security archive as `security-backup.age`. Download immutable copies to the
recovery workstation and record their SHA-256 values. The bucket is temporary
transport, not durable backup storage. Keep both archives and their custody
material off AWS before you destroy the stack.

The replacement server role can download those same two encrypted objects.
Do not upload a plaintext dump, a release-signing key, an execution-custodian
identity, an unlock secret or a plaintext database URL.

The recovery workstation also needs `pg_restore` of the dump's major version or
newer. An older client cannot validate a newer custom archive. Use an approved,
isolated recovery environment if you cannot install that client on the workstation.

Run `restore-drill` on the recovery workstation with the encrypted backup identity
and its anonymous-pipe passphrase input. Then perform the complete
[fenced fresh-host restore](security-and-operations.md#recovery-authority-and-fresh-host-restore).
In the saved Terraform variable file, set `public_ingress_enabled = false` and
apply that change **before** stopping the runtime or taking the security archive.
It removes the one ingress rule for both 443 origins. Verify the external fence.
Then stop `lindmd` and the edge service. Make the current security backup with
`-confirm-fenced`, retain it off-host, and prepare the offline recovery approvals.
Keep every replica stopped.

For a disposable proof, replace `aws_instance.server` and
`aws_db_instance.deployment` with Terraform while ingress remains disabled.
The separately managed network interface and EIPs retain both public origins.
The proof device remains enrolled. Install the compatible signed package on
the replacement server against the fresh RDS database, with new restricted
credentials and the independently pinned RDS CA. Stop its runtime and edge
service before restore. The helper is a fresh installer, not a restore or an
endpoint/password rotation tool. Use the documented
restore command with the authenticated current security checkpoint, signed newer
recovery epoch, independently trusted execution root and explicit fencing.
Retain restored URL ownership and systemd credential paths. Validate integrations
ciphertext decryption, browser reauthentication, device reconciliation and a newly
authorized real action before removing the external fence. Never report an archive
parse or RDS snapshot restore as this complete drill.

Use SSM port forwarding for the operator's private HTTPS checks. For the proof
device, admit only its security group to port 443 after the authorized restore
has completed. Resolve the unchanged device hostname to the retained private
server address on that device. Keep certificate and hostname verification.
This temporary private path lets you verify reconciliation and a fresh action
while public ingress stays closed. Remove the temporary rule after the drill,
then re-enable public ingress through Terraform only when the checks pass.

Before cleanup, retain the approved signed release, public pins, encrypted backups,
required custody ciphertexts and operator-only recovery identities. Copy anything
required out of the disposable server; its root volume is deleted at termination.
Revoke unused enrollment codes and remove temporary transfer files and private S3
objects. Do not delete the canonical installed credentials or recovery material
while retaining a live service. After installation, staged database URL copies
may be removed only after confirming the installer's canonical copies and CA
copies are retained; the setup code must not enter a log during cleanup.

For a disposable deployment only, review the destroy plan from the same Terraform
state and nonsecret variable file, then apply it. Destroy removes RDS without a
final snapshot under the supplied defaults, both EC2 instances, networking,
EIPs and the transfer bucket **including its objects** (`force_destroy`).
Decide retention **before** that step, not after. Independently created buckets,
manual snapshots and copied backups have their own retention and deletion
requirements. Package removal is not secure erasure and
does not delete an external RDS database. Record cleanup outcomes without secret
contents.

## Recorded AWS installation proof

On 2026-10-15, a fresh deployment in `us-east-1` used the supported Terraform
module and the unchanged, self-built signed `0.2.14` release from source
`dea56bc2516e240d12cb5411831636830681895d`.
The cold release build used a fresh Ubuntu VM without swap. Its independently
approved public release key and update root were checked before installation.
No release-signing custody was copied to EC2.

The following steps completed:

- Terraform created the two Ubuntu 24.04 EC2 instances and private RDS in
  473.99 seconds.
- AWS metadata confirmed required IMDSv2, disabled IPv6 metadata, encrypted EC2
  root volumes, encrypted private PostgreSQL 18.6 and the required resource tags.
  RDS enforced SSL and SCRAM password encryption. Its master password remained
  in the RDS-managed Secrets Manager secret.
- The signed native installer completed in 111.13 seconds with external runtime
  and migration credentials, `verify-full` and `channel_binding=require`.
  Direct RDS supported SCRAM channel binding; no `prefer` override was used.
- The PostgreSQL cluster policy was `false`. `pg_conftool` was absent before
  the native installer. No operator-installed `postgresql-common` workaround
  was used, and the completed installation had no local PostgreSQL cluster.
- A live check allowed the root IMDSv2 token request and blocked the same request
  from the `lindmd` service user. No token or credential response body was retained.
- Stock Chromium 156.0.8078.4 loaded the real HTTPS setup control after importing
  the authenticated deployment CA. It used no certificate-error bypass or TLS
  override. The console and device CAs were distinct.

These results qualify installation and browser TLS, not the complete lifecycle.
First-owner setup, real-device enrollment, managed inventory, evaluated findings,
encrypted backup, fresh-host restore and final cleanup require their own recorded
results. Earlier disposable AWS attempts were destroyed and checked independently.

The maintainer-local evidence directory is
`/home/r/dev/minor/lindm.worktrees/aws-deploy/artifacts/aws-proof/sdk18-qualified-candidate/`.
It is not a public download or part of the repository.

## Local stackd result

The 2026-10-14 local attempt used Terraform 1.15.9 and AWS provider 6.68.0.
Terraform created a real Ubuntu 24.04 QEMU/KVM EC2 guest. The EC2-only apply
and destroy completed. Signed SDK calls also created a real PostgreSQL 17.11
engine. A real client checked commit, rollback and wrong-password rejection.
That loopback database did not use TLS. It is not RDS TLS or channel-binding proof.

The complete production EC2 and RDS apply did not complete. The EIP read API
`DescribeAddressesAttribute` was unavailable. The RDS backend also rejected
`allocated_storage`, which the Terraform provider requires. It did not support
the production SSL-enforcement parameter, managed master secret, encrypted
storage, VPC security groups or backup controls. Do not remove these controls
from the AWS module to make a local emulator pass.

The owner stopped local work before an older-provider attempt. All owned
controllers, guests, engines and imported image resources were cleaned up.
The workstation evidence is in `artifacts/aws-stackd/evidence/`. The separate
bug report is `~/dev/minor/stackd-bugs-from-lindm.md` on that workstation.
This is a partial local result, not a full local installation or AWS proof.
