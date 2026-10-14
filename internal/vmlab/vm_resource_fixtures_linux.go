// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/packaging"
	"lindm/internal/platform"
)

const resourceFixtureRoot = "/var/lib/lindm-resource-lab"
const resourceFileRoot = "/etc/lindm-resource-lab"
const resourceRepositoryID = "d06a3d03-3118-4779-a00f-a5544ff095ad"
const resourcePackageName = "lindm-resource-proof"
const resourceDependencyName = "lindm-resource-dependency"

// resourceRepositoryServer serves the signed fixture repository over HTTPS.
// http.server answers HTTP/1.0 and closes each connection; an ssl socket's
// close never sends the TLS close_notify alert, which OpenSSL 3 clients that
// read to EOF report as "unexpected eof while reading" (APT 3.0 on Debian 13
// then refuses the Release file). Each connection is unwrapped, sending
// close_notify, before it is closed; a peer that never answers bounds the wait.
const resourceRepositoryServer = `import functools, http.server, ssl
class Server(http.server.ThreadingHTTPServer):
    def shutdown_request(self, request):
        try:
            request.settimeout(10)
            request.unwrap()
        except (OSError, ValueError):
            pass
        super().shutdown_request(request)
server = Server(('127.0.0.1', 18449), functools.partial(http.server.SimpleHTTPRequestHandler, directory='/var/lib/lindm-resource-lab/repo'))
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('/var/lib/lindm-resource-lab/https.crt', '/var/lib/lindm-resource-lab/https.key')
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
`

// This is laboratory fixture construction, not a provider or policy program.
// It runs only inside DispatchVM's fresh disposable guest. Both repository
// metadata and RPM payloads are signed; HTTPS uses a guest-local disposable CA.
const resourceFixtureScript = `set -eu
umask 022
test ! -e /var/lib/lindm-resource-lab
test ! -e /etc/lindm-resource-lab
mkdir -m 0755 /var/lib/lindm-resource-lab /etc/lindm-resource-lab
cd /var/lib/lindm-resource-lab
` + nativeOSRelease + `
case "$LINDM_RESOURCE_BACKEND:$ID:${VERSION_ID:-}" in
 *:ubuntu:22.04|*:ubuntu:24.04|*:ubuntu:26.04|*:debian:12|*:debian:13)
  # The image's own OpenPGP verifiers before the lab's build tools (gnupg
  # depends on gpgv) are installed; APT 3.0 itself verifies with sqv.
  dpkg-query -W -f='${Package} ${Version} ${db:Status-Status}\n' gpgv sqv > image-verifiers.txt 2>&1 || true
  # Debian installer images omit acl; the file lane's ACL refusal needs setfacl.
  apt-get update; DEBIAN_FRONTEND=noninteractive apt-get install -y dpkg-dev apt-utils gnupg openssl python3 attr acl curl ;;
 *:fedora:43|*:fedora:44) dnf5 install -y rpm-build rpm-sign createrepo_c gnupg2 openssl python3 python3-libdnf5 attr curl
  # The provider requires the maintained DNF5 (>= 5.4.6.0) release update.
  dnf5 upgrade -y dnf5 libdnf5 libdnf5-cli python3-libdnf5 ;;
 *:rhel:9.*|*:almalinux:9.*|*:rocky:9.*|*:rhel:10.*|*:almalinux:10.*|*:rocky:10.*)
  # DNF4 exact pins require the native versionlock plugin; vendor repositories
  # (registered RHEL or the derivative's own mirrors) supply the build tools.
  dnf install -y rpm-build rpm-sign createrepo_c gnupg2 openssl python3 attr curl acl python3-dnf-plugin-versionlock ;;
 *:almalinux:8.*|*:rocky:8.*)
  # EL8 DNF4 runs on platform-python 3.6; the fixture server needs Python 3.7+.
  dnf install -y rpm-build rpm-sign createrepo_c gnupg2 openssl python39 attr curl acl python3-dnf-plugin-versionlock ;;
 pacman:*|zypper:*) : ;; # registry-selected native prerequisites installed by caller
 *) echo 'resource lane requires Ubuntu 22.04/24.04/26.04, Debian 12/13, Fedora 43/44 or an EL 8/9/10 DNF4 platform' >&2; exit 1 ;;
esac
case "$ID" in
 ubuntu|debian) DEB_ARCH=$(dpkg --print-architecture) ;;
 *) if [ "$LINDM_RESOURCE_BACKEND" = pacman ]; then ALPM_ARCH=$(uname -m); else RPM_ARCH=$(rpm --eval '%{_arch}'); fi ;;
esac
mkdir -m 0700 gnupg
export GNUPGHOME="$PWD/gnupg"
gpg --batch --pinentry-mode loopback --passphrase '' --quick-generate-key 'Disposable resource repository <resource@invalid>' rsa3072 sign 1d
gpg --batch --armor --export > repository.asc
gpg --batch --export > repository.gpg
# Root provisions the approved signer into system RPM trust; the provider
# refuses RPM sources whose key is absent there.
if [ -n "${RPM_ARCH:-}" ]; then rpmkeys --import repository.asc; fi
gpg --batch --with-colons --list-keys > keys.colons
mkdir -m 0700 wrong-gnupg
gpg --homedir "$PWD/wrong-gnupg" --batch --pinentry-mode loopback --passphrase '' --quick-generate-key 'Wrong disposable signer <wrong@invalid>' rsa3072 sign 1d
gpg --homedir "$PWD/wrong-gnupg" --batch --armor --export > wrong.asc
gpg --homedir "$PWD/wrong-gnupg" --batch --export > wrong.gpg
gpg --homedir "$PWD/wrong-gnupg" --batch --with-colons --list-keys > wrong-keys.colons
openssl req -x509 -newkey rsa:3072 -nodes -keyout https.key -out https.crt -days 1 -subj /CN=localhost -addext 'subjectAltName=IP:127.0.0.1,DNS:localhost' -addext 'basicConstraints=critical,CA:TRUE'
chmod 0600 https.key
case "$ID" in
 ubuntu|debian) install -m 0644 https.crt /usr/local/share/ca-certificates/lindm-resource-lab.crt; update-ca-certificates ;;
 *) if [ "$LINDM_RESOURCE_BACKEND" = zypper ]; then install -m 0644 https.crt /etc/pki/trust/anchors/lindm-resource-lab.pem; update-ca-certificates;
 elif [ "$LINDM_RESOURCE_BACKEND" = pacman ]; then install -m 0644 https.crt /etc/ca-certificates/trust-source/anchors/lindm-resource-lab.crt; update-ca-trust;
 else install -m 0644 https.crt /etc/pki/ca-trust/source/anchors/lindm-resource-lab.crt; update-ca-trust; fi ;;
esac
mkdir repo
for version in 1.0 2.0; do
 for name in lindm-resource-dependency lindm-resource-proof lindm-resource-crash; do
  mkdir -p "build/$name-$version/usr/share/$name"
  printf '%s\n' "$version" > "build/$name-$version/usr/share/$name/version"
  if [ "$name" != lindm-resource-dependency ]; then
   mkdir -p "build/$name-$version/usr/bin"
   cat > "build/$name-$version/usr/bin/$name" <<APP
#!/bin/sh
set -eu
test -r /usr/share/lindm-resource-dependency/version
test -s /var/lib/lindm-resource-lab/maintainer.log
cat /usr/share/$name/version
APP
   chmod 0755 "build/$name-$version/usr/bin/$name"
  fi
  if [ -n "${DEB_ARCH:-}" ]; then
   mkdir "build/$name-$version/DEBIAN"
   cat > "build/$name-$version/DEBIAN/control" <<EOF
Package: $name
Version: $version-1
Architecture: $DEB_ARCH
Maintainer: Disposable laboratory <resource@invalid>
Description: Disposable native resource qualification
EOF
   if [ "$name" != lindm-resource-dependency ]; then
    printf 'Depends: lindm-resource-dependency (>= 1.0-1)\n' >> "build/$name-$version/DEBIAN/control"
    cat > "build/$name-$version/DEBIAN/postinst" <<EOF
#!/bin/sh
set -eu
printf '%s\n' '$version-1 configure' >> /var/lib/lindm-resource-lab/maintainer.log
if test '$name' = lindm-resource-crash && test -e /var/lib/lindm-resource-lab/interrupt; then
 printf 'entered\n' >> /var/lib/lindm-resource-lab/interrupt.log
 sleep 300
fi
EOF
    chmod 0755 "build/$name-$version/DEBIAN/postinst"
   fi
   # Like every distribution archive package (dh_md5sums), ship md5sums:
   # approved adoption compares them with the installed dpkg records.
   (cd "build/$name-$version" && find usr -type f -exec md5sum {} + | LC_ALL=C sort -k 2 > DEBIAN/md5sums)
   dpkg-deb --root-owner-group --build "build/$name-$version" "repo/$name-$version.deb"
  elif [ -n "${ALPM_ARCH:-}" ]; then
   cat > "build/$name-$version/.PKGINFO" <<EOF
pkgname = $name
pkgbase = $name
pkgver = $version-1
pkgdesc = Disposable native resource qualification
builddate = 1
packager = Disposable laboratory
size = 4096
arch = $ALPM_ARCH
license = MIT
EOF
   if [ "$name" != lindm-resource-dependency ]; then
    printf 'depend = lindm-resource-dependency>=1.0-1\n' >> "build/$name-$version/.PKGINFO"
    cat > "build/$name-$version/.INSTALL" <<EOF
post_install() {
 printf '%s\n' '$version-1 configure' >> /var/lib/lindm-resource-lab/maintainer.log
 if test '$name' = lindm-resource-crash && test -e /var/lib/lindm-resource-lab/interrupt; then
  printf 'entered\n' >> /var/lib/lindm-resource-lab/interrupt.log
  sleep 300
 fi
}
post_upgrade() { post_install; }
EOF
   fi
   if [ "$name" = lindm-resource-dependency ]; then
    bsdtar --zstd -cf "repo/$name-$version-1-$ALPM_ARCH.pkg.tar.zst" -C "build/$name-$version" .PKGINFO usr
   else
    bsdtar --zstd -cf "repo/$name-$version-1-$ALPM_ARCH.pkg.tar.zst" -C "build/$name-$version" .PKGINFO .INSTALL usr
   fi
   gpg --batch --yes --detach-sign "repo/$name-$version-1-$ALPM_ARCH.pkg.tar.zst"
  else
   mkdir -p rpmbuild/BUILD rpmbuild/BUILDROOT rpmbuild/RPMS rpmbuild/SOURCES rpmbuild/SPECS rpmbuild/SRPMS
   cat > "rpmbuild/SPECS/$name.spec" <<EOF
Name: $name
Version: $version
Release: 1
Summary: Disposable native resource qualification
License: MIT
BuildArch: $RPM_ARCH
AutoReqProv: no
EOF
   if [ "$name" != lindm-resource-dependency ]; then printf 'Requires: lindm-resource-dependency >= 1.0-1\n' >> "rpmbuild/SPECS/$name.spec"; fi
   cat >> "rpmbuild/SPECS/$name.spec" <<EOF
%description
Disposable native resource qualification.
%install
mkdir -p %{buildroot}/usr
cp -a /var/lib/lindm-resource-lab/build/$name-$version/usr/. %{buildroot}/usr/
%files
/usr/share/$name
EOF
   if [ "$name" != lindm-resource-dependency ]; then
    cat >> "rpmbuild/SPECS/$name.spec" <<EOF
/usr/bin/$name
%post
printf '%s\n' '$version-1 configure' >> /var/lib/lindm-resource-lab/maintainer.log
if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled; then printf 'scriptlet-context %s\n' "\$(id -Z)" >> /var/lib/lindm-resource-lab/maintainer.log; fi
if test '$name' = lindm-resource-crash && test -e /var/lib/lindm-resource-lab/interrupt; then
 printf 'entered\n' >> /var/lib/lindm-resource-lab/interrupt.log
 sleep 300
fi
EOF
   fi
   rpmbuild --define "_topdir $PWD/rpmbuild" -bb "rpmbuild/SPECS/$name.spec"
   cp "rpmbuild/RPMS/$RPM_ARCH/$name-$version-1.$RPM_ARCH.rpm" repo/
  fi
 done
done
if [ -n "${DEB_ARCH:-}" ]; then
 mkdir -p "repo/dists/stable/main/binary-$DEB_ARCH"
 (cd repo; dpkg-scanpackages --multiversion . /dev/null > "dists/stable/main/binary-$DEB_ARCH/Packages")
 gzip -k "repo/dists/stable/main/binary-$DEB_ARCH/Packages"
 (cd repo; apt-ftparchive -o APT::FTPArchive::Release::Origin=LindmResourceLab -o APT::FTPArchive::Release::Suite=stable -o APT::FTPArchive::Release::Codename=stable -o "APT::FTPArchive::Release::Architectures=$DEB_ARCH" -o APT::FTPArchive::Release::Components=main release dists/stable > dists/stable/Release)
 gpg --batch --yes --clearsign -o repo/dists/stable/InRelease repo/dists/stable/Release
 gpg --batch --yes --armor --detach-sign -o repo/dists/stable/Release.gpg repo/dists/stable/Release
elif [ -n "${ALPM_ARCH:-}" ]; then
 # Pacman's database contains one version per package; publish immutable
 # version-specific repositories and switch the approved source between phases.
 for version in 1.0 2.0; do
  mkdir "repo/$version"
  cp repo/*-"$version"-1-*.pkg.tar.zst* "repo/$version/"
  # Arch's own sync databases carry %PGPSIG%, which the provider binds before
  # download; pacman >= 6.1 repo-add embeds it only with --include-sigs.
  repo-add --sign --include-sigs "repo/$version/lindm-resource-lab.db.tar.gz" repo/"$version"/*.pkg.tar.zst
 done
else
 if [ "$LINDM_RESOURCE_BACKEND" = zypper ]; then
  # Real signed alternate-architecture solvables make the lock oracle prove
  # conjunction, not merely absence of a package from the fixture universe.
  for version in 1.0 2.0; do
   cat > rpmbuild/SPECS/lock-noarch.spec <<EOF
Name: lindm-resource-proof
Version: $version
Release: 1
Summary: Native lock architecture witness
License: MIT
BuildArch: noarch
%description
Signed native architecture witness, never installed by this lane.
%install
mkdir -p %{buildroot}/usr/share/lindm-resource-lock-witness
printf '%s\\n' '$version' > %{buildroot}/usr/share/lindm-resource-lock-witness/version
%files
/usr/share/lindm-resource-lock-witness/version
EOF
   rpmbuild --define "_topdir $PWD/rpmbuild" -bb rpmbuild/SPECS/lock-noarch.spec
   cp "rpmbuild/RPMS/noarch/lindm-resource-proof-$version-1.noarch.rpm" repo/
  done
 fi
 for package in repo/*.rpm; do rpmsign --define '_gpg_name Disposable resource repository' --define "_gpg_path $GNUPGHOME" --define '_gpg_sign_cmd_extra_args --pinentry-mode loopback --passphrase ""' --addsign "$package"; done
 createrepo_c repo
 gpg --batch --yes --armor --detach-sign repo/repodata/repomd.xml
fi
cat > serve.py <<'PY'
` + resourceRepositoryServer + `PY
if command -v restorecon >/dev/null 2>&1; then restorecon -RF /var/lib/lindm-resource-lab /etc/lindm-resource-lab; test "$(getenforce)" = Enforcing; fi
SERVE_PYTHON=/usr/bin/python3
if [ -x /usr/bin/python3.9 ] && [ "$ID" != fedora ] && [ -z "${DEB_ARCH:-}" ]; then SERVE_PYTHON=/usr/bin/python3.9; fi
# An installed, enabled unit (not a transient one) keeps the signed repository
# available after the sysctl and firewall lanes' real guest reboots, which run
# before the package interruption scenario. Lab units stay in lindm-lab-*: the
# product's lindm-resource-<action> helper names are matched by lane oracles.
cat > /etc/systemd/system/lindm-lab-resource-repository.service <<UNIT
[Unit]
Description=Disposable signed lindm resource lab repository
After=network-online.target
[Service]
Type=exec
ExecStart=$SERVE_PYTHON /var/lib/lindm-resource-lab/serve.py
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now lindm-lab-resource-repository.service
curl --fail --retry 10 --retry-connrefused --retry-delay 1 https://127.0.0.1:18449/ -o /dev/null
if [ -n "${DEB_ARCH:-}" ]; then
 # The repository is signed; the lab's gnupg pulled gpgv, which the image may
 # lack (Debian 13's APT verifies with sqv). Restoring the image's own verifier
 # set keeps the provider from depending on a lab-installed tool.
 if ! awk '$1=="gpgv" && $NF=="installed" {found=1} END {exit !found}' image-verifiers.txt; then
  test "$(apt-get -s purge gnupg gpgv | awk '$1=="Purg"{print $2}' | sort | tr '\n' ' ')" = 'gnupg gpgv '
  DEBIAN_FRONTEND=noninteractive apt-get purge -y gnupg gpgv > purged-verifiers.txt 2>&1
  test ! -e /usr/bin/gpgv
 fi
 dpkg-query -W -f='${Package} ${Version} ${db:Status-Status}\n' gpgv gnupg sqv > fixture-verifiers.txt 2>&1 || true
fi
`

// rollingResourcePrerequisites returns the provisioning transaction (empty
// when the golden installed the tools from its installer media) and the
// independent presence query for a rolling guest's resource prerequisites.
// A release row's own list (a derivative's media) overrides its base's.
func rollingResourcePrerequisites(row *platform.Release, backend platform.Backend, snapshot bool) (install, query string, err error) {
	names := row.Lab.ResourcePackages
	if len(names) == 0 {
		names = row.Native().Lab.ResourcePackages
	}
	if len(names) == 0 {
		return "", "", errors.New("resource fixture prerequisites absent from platform registry")
	}
	query = "rpm -q"
	if backend == platform.BackendPacman {
		query = "pacman -Q"
	}
	for _, name := range names {
		query += " " + nativeQuote(name)
	}
	if row.Lab.Guest.FromInstaller {
		return "", query, nil
	}
	if !snapshot {
		return "", "", errors.New("rolling resource prerequisites require the approved repository snapshot")
	}
	// Provision only the disposable guest against its already pinned origin.
	// A cloud image may precede the selected snapshot: never acquire Arch
	// prerequisites through a partial upgrade or a moving mirror.
	install = "zypper --non-interactive refresh; zypper --non-interactive --no-refresh dist-upgrade --no-allow-vendor-change; zypper --non-interactive --no-refresh install --no-recommends"
	if backend == platform.BackendPacman {
		install = "pacman -Syu --needed --noconfirm"
	}
	for _, name := range names {
		install += " " + nativeQuote(name)
	}
	return install, query, nil
}

func setupVMResourceFixtures(ctx context.Context, packages *nativeGuestPackages, architecture string, selected map[string]bool) error {
	if packages.backend == platform.BackendPacman || packages.backend == platform.BackendZypper {
		observed, err := packages.vm.run(ctx, ". /etc/os-release; printf '%s\\n%s\\n' \"$ID\" \"${VERSION_ID-}\"", nil, 4096, 15*time.Second)
		if err != nil {
			return err
		}
		id, version, _ := strings.Cut(strings.TrimSpace(string(observed)), "\n")
		install, query, err := rollingResourcePrerequisites(platform.Identify(platform.OSRelease{ID: id, VersionID: version}), packages.backend, packages.rollingSnapshot != nil)
		if err != nil {
			return err
		}
		if install != "" {
			// Native package managers report progress and already-current packages
			// on stderr. Require transaction success, then independently query the
			// complete declared prerequisite set below; silence is not an oracle.
			result, err := packages.vm.runResult(ctx, "sudo -n sh -eu -c "+nativeQuote(install), nil, 4<<20, 30*time.Minute)
			if err != nil {
				return fmt.Errorf("provision signed rolling resource prerequisites: %w", err)
			}
			if result.ExitCode != 0 {
				return fmt.Errorf("provision signed rolling resource prerequisites: native exit %d (stdout bytes %d, stderr bytes %d)", result.ExitCode, len(result.Stdout), len(result.Stderr))
			}
		}
		if err := lifecycleCommand(ctx, packages.vm, "require pinned resource native prerequisites", query); err != nil {
			return err
		}
	}
	script, err := packages.vm.nativeScript(resourceFixtureScript)
	if err != nil {
		return err
	}
	if err := packages.uploadBytes(ctx, nativeGuestDir+"/resource-fixtures.sh", []byte(script)); err != nil {
		return err
	}
	// Native package tools report progress on stderr; the script's exit status
	// and the separate signed-fixture evidence are the outcome, not silence.
	if _, err := packages.vm.run(ctx, "sudo -n env LINDM_RESOURCE_BACKEND="+nativeQuote(string(packages.backend))+" /bin/sh "+nativeQuote(nativeGuestDir+"/resource-fixtures.sh")+" 2>&1", nil, 4<<20, 15*time.Minute); err != nil {
		return fmt.Errorf("construct signed native resource repository: %w", err)
	}
	data, err := packages.vm.run(ctx, "sudo -n cat /etc/lindm/executor.json", nil, 128<<10, 15*time.Second)
	if err != nil {
		return err
	}
	config := new(agentv1.AgentConfig)
	if err := protojson.Unmarshal(data, config); err != nil {
		return err
	}
	keyPath := resourceFixtureRoot + "/repository.gpg"
	if packages.backend.PackageDB() == platform.PackageDBRPM {
		keyPath = resourceFixtureRoot + "/repository.asc"
	}
	key, err := packages.vm.run(ctx, "sudo -n cat "+nativeQuote(keyPath), nil, 1<<20, 15*time.Second)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(key)
	artifact := &resourcev1.ArtifactRef{ArtifactId: "66db4aa6-9bcc-45f5-b725-4ed529533879", Sha256: digest[:], SizeBytes: uint64(len(key))}
	repository := &resourcev1.RepositoryDesired{RepositoryId: resourceRepositoryID, Presence: resourcev1.Presence_PRESENCE_PRESENT}
	source := &agentv1.NativePackageSource{Repository: repository, SigningKeyFile: keyPath, SigningKeySha256: digest[:]}
	if packages.backend.PackageDB() == platform.PackageDBRPM || packages.backend == platform.BackendPacman {
		listed, err := packages.vm.run(ctx, "sudo -n cat "+resourceFixtureRoot+"/keys.colons", nil, 16384, 15*time.Second)
		if err != nil {
			return err
		}
		for line := range strings.SplitSeq(string(listed), "\n") {
			fields := strings.Split(line, ":")
			if len(fields) > 9 && fields[0] == "fpr" {
				source.RpmSigningKeyFingerprint = fields[9]
				break
			}
		}
		if source.RpmSigningKeyFingerprint == "" {
			return errors.New("native repository signer fingerprint absent")
		}
		repository.Source = &resourcev1.RepositoryDesired_Rpm{Rpm: &resourcev1.RpmRepository{NativeId: "lindm-resource-lab", Location: &resourcev1.RpmRepository_BaseUrls{BaseUrls: &resourcev1.RepositoryURLs{Urls: []string{"https://127.0.0.1:18449"}}}, SigningKeys: []*resourcev1.ArtifactRef{artifact}, RequireMetadataSignature: true, RequirePackageSignature: true}}
		if packages.backend == platform.BackendPacman {
			source.AlpmSigningKeyFingerprint = source.RpmSigningKeyFingerprint
			source.RpmSigningKeyFingerprint = ""
			repository.Source = &resourcev1.RepositoryDesired_Alpm{Alpm: &resourcev1.AlpmRepository{NativeName: "lindm-resource-lab", SnapshotUri: "https://127.0.0.1:18449/1.0", Architecture: newResourcePackaging(packages.backend, architecture).nativeArch(), SigningKeys: []*resourcev1.ArtifactRef{artifact}}}
		}
	} else {
		repository.Source = &resourcev1.RepositoryDesired_Apt{Apt: &resourcev1.AptRepository{Uri: "https://127.0.0.1:18449", Suite: "stable", Components: []string{"main"}, Architectures: []string{architecture}, SigningKey: artifact}}
	}
	config.PackageProvider = &agentv1.NativePackageProviderConfig{Sources: []*agentv1.NativePackageSource{source}}
	config.FileProvider = &agentv1.NativeFileProviderConfig{AllowedRoots: []string{resourceFileRoot}, KernelModuleBlocklist: selected["modules"]}
	if selected["accounts"] || selected["sysctl"] || selected["definitions"] || selected["secret-password"] {
		if err := setupHostResourceFixtures(ctx, packages.vm); err != nil {
			return err
		}
		provisionHostResourceRoots(config)
	}
	install := "install -o root -g root -m 0600 " + nativeGuestDir + "/resource-executor.json /etc/lindm/executor.json; "
	if selected["local-admin"] {
		script, err := packages.vm.nativeScript(localAdminFixtureScript)
		if err != nil {
			return err
		}
		if err := lifecycleCommand(ctx, packages.vm, "create managed local-admin account", script); err != nil {
			return err
		}
		// Root's local allowlist is the only native authority for rotation;
		// the reviewed sandbox exception is generated from it before restart.
		config.ActionProvider = &agentv1.DeviceActionProviderConfig{LocalAdminAccounts: []string{localAdminLabAccount}}
		install += packaging.BinaryPath + " action-sandbox -install; systemctl daemon-reload; "
	}
	if err := protovalidate.Validate(config); err != nil {
		return err
	}
	encoded, err := protojson.Marshal(config)
	if err != nil {
		return err
	}
	if err := packages.uploadBytes(ctx, nativeGuestDir+"/resource-executor.json", encoded); err != nil {
		return err
	}
	return lifecycleCommand(ctx, packages.vm, "provision explicit native resource roots and signed source", install+"systemctl restart lindm-executor.service")
}
