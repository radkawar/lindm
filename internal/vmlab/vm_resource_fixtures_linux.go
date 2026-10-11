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
)

const resourceFixtureRoot = "/var/lib/lindm-resource-lab"
const resourceFileRoot = "/etc/lindm-resource-lab"
const resourceRepositoryID = "d06a3d03-3118-4779-a00f-a5544ff095ad"
const resourcePackageName = "lindm-resource-proof"
const resourceDependencyName = "lindm-resource-dependency"

// This is laboratory fixture construction, not a provider or policy program.
// It runs only inside DispatchVM's fresh disposable guest. Both repository
// metadata and RPM payloads are signed; HTTPS uses a guest-local disposable CA.
const resourceFixtureScript = `set -eu
umask 022
test ! -e /var/lib/lindm-resource-lab
test ! -e /etc/lindm-resource-lab
mkdir -m 0755 /var/lib/lindm-resource-lab /etc/lindm-resource-lab
cd /var/lib/lindm-resource-lab
. /etc/os-release
case "$ID:$VERSION_ID" in
 ubuntu:24.04|ubuntu:26.04) apt-get update; DEBIAN_FRONTEND=noninteractive apt-get install -y dpkg-dev apt-utils gnupg openssl python3 attr curl ;;
 fedora:44) dnf5 install -y rpm-build rpm-sign createrepo_c gnupg2 openssl python3 python3-libdnf5 attr curl
  # The provider requires the maintained DNF5 (>= 5.4.6.0) release update.
  dnf5 upgrade -y dnf5 libdnf5 libdnf5-cli python3-libdnf5 ;;
 rhel:9.*|almalinux:9.*|rocky:9.*|rhel:10.*|almalinux:10.*|rocky:10.*)
  # DNF4 exact pins require the native versionlock plugin; vendor repositories
  # (registered RHEL or the derivative's own mirrors) supply the build tools.
  dnf install -y rpm-build rpm-sign createrepo_c gnupg2 openssl python3 attr curl acl python3-dnf-plugin-versionlock ;;
 almalinux:8.*|rocky:8.*)
  # EL8 DNF4 runs on platform-python 3.6; the fixture server needs Python 3.7+.
  dnf install -y rpm-build rpm-sign createrepo_c gnupg2 openssl python39 attr curl acl python3-dnf-plugin-versionlock ;;
 *) echo 'resource lane requires Ubuntu 24.04/26.04, Fedora 44 or an EL 8/9/10 DNF4 platform' >&2; exit 1 ;;
esac
case "$ID" in
 ubuntu) DEB_ARCH=$(dpkg --print-architecture) ;;
 *) RPM_ARCH=$(rpm --eval '%{_arch}') ;;
esac
mkdir -m 0700 gnupg
export GNUPGHOME="$PWD/gnupg"
gpg --batch --pinentry-mode loopback --passphrase '' --quick-generate-key 'Disposable resource repository <resource@invalid>' rsa3072 sign 1d
gpg --batch --armor --export > repository.asc
gpg --batch --export > repository.gpg
# Root provisions the approved signer into system RPM trust; the provider
# refuses RPM sources whose key is absent there.
if [ "$ID" != ubuntu ]; then rpmkeys --import repository.asc; fi
gpg --batch --with-colons --list-keys > keys.colons
mkdir -m 0700 wrong-gnupg
gpg --homedir "$PWD/wrong-gnupg" --batch --pinentry-mode loopback --passphrase '' --quick-generate-key 'Wrong disposable signer <wrong@invalid>' rsa3072 sign 1d
gpg --homedir "$PWD/wrong-gnupg" --batch --armor --export > wrong.asc
gpg --homedir "$PWD/wrong-gnupg" --batch --export > wrong.gpg
gpg --homedir "$PWD/wrong-gnupg" --batch --with-colons --list-keys > wrong-keys.colons
openssl req -x509 -newkey rsa:3072 -nodes -keyout https.key -out https.crt -days 1 -subj /CN=localhost -addext 'subjectAltName=IP:127.0.0.1,DNS:localhost' -addext 'basicConstraints=critical,CA:TRUE'
chmod 0600 https.key
case "$ID" in
 ubuntu) install -m 0644 https.crt /usr/local/share/ca-certificates/lindm-resource-lab.crt; update-ca-certificates ;;
 *) install -m 0644 https.crt /etc/pki/ca-trust/source/anchors/lindm-resource-lab.crt; update-ca-trust ;;
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
  if [ "$ID" = ubuntu ]; then
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
   dpkg-deb --root-owner-group --build "build/$name-$version" "repo/$name-$version.deb"
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
if [ "$ID" = ubuntu ]; then
 mkdir -p "repo/dists/stable/main/binary-$DEB_ARCH"
 (cd repo; dpkg-scanpackages --multiversion . /dev/null > "dists/stable/main/binary-$DEB_ARCH/Packages")
 gzip -k "repo/dists/stable/main/binary-$DEB_ARCH/Packages"
 (cd repo; apt-ftparchive -o APT::FTPArchive::Release::Origin=LindmResourceLab -o APT::FTPArchive::Release::Suite=stable -o APT::FTPArchive::Release::Codename=stable -o "APT::FTPArchive::Release::Architectures=$DEB_ARCH" -o APT::FTPArchive::Release::Components=main release dists/stable > dists/stable/Release)
 gpg --batch --yes --clearsign -o repo/dists/stable/InRelease repo/dists/stable/Release
 gpg --batch --yes --armor --detach-sign -o repo/dists/stable/Release.gpg repo/dists/stable/Release
else
 for package in repo/*.rpm; do rpmsign --define '_gpg_name Disposable resource repository' --define "_gpg_path $GNUPGHOME" --define '_gpg_sign_cmd_extra_args --pinentry-mode loopback --passphrase ""' --addsign "$package"; done
 createrepo_c repo
 gpg --batch --yes --armor --detach-sign repo/repodata/repomd.xml
fi
cat > serve.py <<'PY'
import functools, http.server, ssl
server = http.server.ThreadingHTTPServer(('127.0.0.1', 18449), functools.partial(http.server.SimpleHTTPRequestHandler, directory='/var/lib/lindm-resource-lab/repo'))
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('/var/lib/lindm-resource-lab/https.crt', '/var/lib/lindm-resource-lab/https.key')
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
PY
if command -v restorecon >/dev/null 2>&1; then restorecon -RF /var/lib/lindm-resource-lab /etc/lindm-resource-lab; test "$(getenforce)" = Enforcing; fi
SERVE_PYTHON=/usr/bin/python3
if [ -x /usr/bin/python3.9 ] && [ "$ID" != fedora ] && [ "$ID" != ubuntu ]; then SERVE_PYTHON=/usr/bin/python3.9; fi
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
`

func setupVMResourceFixtures(ctx context.Context, packages *nativeGuestPackages, architecture string, selected map[string]bool) error {
	if err := packages.uploadBytes(ctx, nativeGuestDir+"/resource-fixtures.sh", []byte(resourceFixtureScript)); err != nil {
		return err
	}
	// Native package tools report progress on stderr; the script's exit status
	// and the separate signed-fixture evidence are the outcome, not silence.
	if _, err := packages.vm.run(ctx, "sudo -n /bin/sh "+nativeQuote(nativeGuestDir+"/resource-fixtures.sh")+" 2>&1", nil, 4<<20, 15*time.Minute); err != nil {
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
	if packages.family == familyDNF {
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
	if packages.family == familyDNF {
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
	} else {
		repository.Source = &resourcev1.RepositoryDesired_Apt{Apt: &resourcev1.AptRepository{Uri: "https://127.0.0.1:18449", Suite: "stable", Components: []string{"main"}, Architectures: []string{architecture}, SigningKey: artifact}}
	}
	config.PackageProvider = &agentv1.NativePackageProviderConfig{Sources: []*agentv1.NativePackageSource{source}}
	config.FileProvider = &agentv1.NativeFileProviderConfig{AllowedRoots: []string{resourceFileRoot}}
	if selected["accounts"] || selected["sysctl"] || selected["definitions"] || selected["secret-password"] {
		if err := setupHostResourceFixtures(ctx, packages.vm); err != nil {
			return err
		}
		provisionHostResourceRoots(config)
	}
	install := "install -o root -g root -m 0600 " + nativeGuestDir + "/resource-executor.json /etc/lindm/executor.json; "
	if selected["local-admin"] {
		if err := lifecycleCommand(ctx, packages.vm, "create managed local-admin account", localAdminFixtureScript); err != nil {
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
