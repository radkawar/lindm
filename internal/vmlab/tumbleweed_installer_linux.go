//go:build linux

package vmlab

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/platform"
)

// tumbleweedInstallerEdition names signed openSUSE Tumbleweed snapshot DVD
// media. The DVD carries the installation repository for exactly one snapshot,
// so the base system is pinned by the authenticated ISO digest. Packages absent
// from the DVD come from the retained, signed repository snapshot closure.
const tumbleweedInstallerEdition = "dvd"

// Bump when the AutoYaST profile or machine layout changes.
const tumbleweedInstallerRecipeVersion = "opensuse-tumbleweed-dvd-autoyast-v7"

// tumbleweedSSHDOrdering closes a vendor boot race. Tumbleweed starts sshd and
// systemd-user-sessions in parallel once cloud-init's network stage finishes;
// until user sessions are permitted, pam_nologin (requisite in the sshd account
// stack) refuses every non-root login, which a client sees as an authentication
// failure. The lab deliberately treats that as terminal, so a reboot probe that
// lands in the window failed a lifecycle lane. Order sshd after the unit.
const tumbleweedSSHDOrdering = "/etc/systemd/system/sshd.service.d/10-lindm-lab-user-sessions.conf"

// tumbleweedRepositoryAlias names the online OSS repository in the profile and
// in the installed system.
const tumbleweedRepositoryAlias = "lindm-tumbleweed-oss"

func tumbleweedInstallerImage(m *labv1.ImageManifest) (*installerImage, error) {
	architecture, _, err := encryptedInstallerArchitecture(m.GetArchitecture())
	if err != nil {
		return nil, err
	}
	if _, err := time.Parse("20060102", m.GetVersion()); err != nil || len(m.GetVersion()) != 8 {
		return nil, errors.New("tumbleweed installer requires a dated snapshot version")
	}
	release := platform.ForManifest(m.GetDistribution(), m.GetVersion())
	if release.Lab.Installer != platform.AutoYaST || (m.GetEdition() != tumbleweedInstallerEdition && m.GetEdition() != "dvd-encrypted-lab") || m.GetRelease() != "Snapshot"+m.GetVersion() ||
		m.GetImageFilename() != "openSUSE-Tumbleweed-DVD-"+architecture+"-Snapshot"+m.GetVersion()+"-Media.iso" ||
		m.GetChecksumMode() != labv1.ChecksumMode_CHECKSUM_MODE_DETACHED {
		return nil, errors.New("tumbleweed installed image requires a signed snapshot-pinned Tumbleweed DVD manifest")
	}
	version := m.GetVersion()
	_, pinnedPackages, err := tumbleweedSnapshotPackageSelection(release, version, architecture)
	if err != nil {
		return nil, err
	}
	snapshot := new(tumbleweedSnapshotRepository)
	return &installerImage{
		label:     "tumbleweed",
		installer: platform.AutoYaST,
		cache:     "tumbleweed-installed",
		version:   tumbleweedInstallerRecipeVersion,
		// YaST resolves the full DVD repository in memory.
		memoryMiB: 4096,
		snapshot:  snapshot,
		recipe: func(disk, architecture, sourceDigest, login, hostPrivate, hostPublic string) ([]byte, error) {
			return tumbleweedInstallerRecipeWithEncryption(release, version, disk, architecture, sourceDigest, login, hostPrivate, hostPublic, "", "", false, snapshot)
		},
		probes: []installedProbe{
			{"distribution", ". /etc/os-release; test \"$ID\" = " + nativeQuote(release.ID)},
			// os-release VERSION_ID is the installed snapshot date.
			{"version", ". /etc/os-release; test \"$VERSION_ID\" = " + nativeQuote(version)},
			{"source_marker", installerSourceMarkerProbe(installerSourceMarkerPath, m.GetSha256())},
			{"root_filesystem", "test \"$(findmnt -n -o FSTYPE /)\" = btrfs"},
			{"package_tool", "command -v zypper >/dev/null && command -v rpm >/dev/null"},
			{"privilege_tool", "command -v sudo >/dev/null"},
			{"sshd_after_user_sessions", "systemctl show sshd.service -p After --value | tr ' ' '\\n' | grep -qx systemd-user-sessions.service"},
			// The vendor TW cloud configuration, not MicroOS's alternative.
			{"cloud_config", "rpm -q cloud-init-config-suse >/dev/null"},
			{"exact_snapshot_packages", pinnedPackages},
			// Fresh firmware variables boot only the removable-media path.
			{"removable_boot", "test -s /boot/efi/EFI/BOOT/" + tumbleweedRemovableLoader(architecture)},
		},
	}, nil
}

func tumbleweedRemovableLoader(architecture string) string {
	if architecture == "aarch64" {
		return "bootaa64.efi"
	}
	return "bootx64.efi"
}

// The server is started from a verified content-addressed snapshot, not a new
// vendor authority. RPM and repository signatures still use the vendor key.
type tumbleweedSnapshotRepository struct {
	URL   string
	CAPEM []byte
}

// Both golden variants use the same snapshot-bound AutoYaST path. An explicit
// unencrypted /boot keeps GRUB outside the LUKS2 root; systemd in the initrd
// owns unlocking, including TPM tokens enrolled later by the signed action.
func tumbleweedInstallerRecipeWithEncryption(release *platform.Release, version, disk, architecture, sourceDigest, login, hostPrivate, hostPublic, passphrase, desktop string, tpmBoot bool, snapshot *tumbleweedSnapshotRepository) ([]byte, error) {
	return tumbleweedInstallerProfile(release, version, disk, architecture, sourceDigest, login, hostPrivate, hostPublic, passphrase, desktop, tpmBoot, snapshot, false)
}

// captureOnly is reachable only from the signed-DVD native solver bootstrap,
// never from ordinary/encrypted golden admission. It has no network repository
// or cloud-init dependency; its fixed SSH identity exists only for this run.
func tumbleweedInstallerProfile(release *platform.Release, version, disk, architecture, sourceDigest, login, hostPrivate, hostPublic, passphrase, desktop string, tpmBoot bool, snapshot *tumbleweedSnapshotRepository, captureOnly bool) ([]byte, error) {
	if disk != "/dev/vda" && disk != "/dev/sda" && disk != "/dev/nvme0n1" {
		return nil, errors.New("tumbleweed installer requires an owned guest root disk")
	}
	architecture, console, err := encryptedInstallerArchitecture(architecture)
	if err != nil {
		return nil, err
	}
	login, err = encryptedInstallerPublicKey(login)
	if err != nil {
		return nil, err
	}
	hostPublic, err = encryptedInstallerPublicKey(hostPublic)
	if err != nil {
		return nil, err
	}
	host, err := ssh.ParsePrivateKey([]byte(hostPrivate))
	if err != nil || string(ssh.MarshalAuthorizedKey(host.PublicKey())) != hostPublic {
		return nil, errors.New("tumbleweed installer SSH host key pair differs")
	}
	if len(sourceDigest) != 64 || strings.Trim(sourceDigest, "0123456789abcdef") != "" {
		return nil, errors.New("tumbleweed installer requires verified source SHA256")
	}
	var addOn, preScript, trust, cloudPackages string
	recommended, enhancedBase := "true", "<pattern>enhanced_base</pattern>"
	if captureOnly {
		if passphrase != "" || desktop != "" || tpmBoot || snapshot != nil || release == nil {
			return nil, errors.New("capture bootstrap cannot select an encrypted, desktop or network installer")
		}
		recommended, enhancedBase = "false", ""
		preScript = `<pre-scripts config:type="list"><script><filename>lindm-bootstrap-stage</filename><interpreter>shell</interpreter><source><![CDATA[` + tumbleweedInstallerStage("profile-pre") + `]]></source></script></pre-scripts>`
	} else {
		repository, before, ca, repositoryErr := tumbleweedInstallerRepository(snapshot)
		if repositoryErr != nil {
			return nil, repositoryErr
		}
		preScript, trust = before, ca
		addOn = `<add-on><add_on_others config:type="list"><listentry><media_url>` + repository + `</media_url><alias>` + tumbleweedRepositoryAlias + `</alias><name>openSUSE Tumbleweed OSS (snapshot-bound)</name><priority config:type="integer">120</priority><ask_on_error config:type="boolean">false</ask_on_error></listentry></add_on_others></add-on>`
		cloudPackages = "<package>cloud-init</package><package>cloud-init-config-suse</package>"
	}
	provision := "set -eu\n"
	if captureOnly {
		provision += tumbleweedInstallerStage("provision-start")
	}
	provision += trust + encryptedInstallerProvision(login, hostPrivate, hostPublic)
	if !captureOnly {
		provision += "install -d -m 0755 /etc/cloud/cloud.cfg.d\nprintf '%s\\n' 'datasource_list: [ NoCloud ]' 'network: {config: disabled}' > /etc/cloud/cloud.cfg.d/99-lindm-lab.cfg\n"
	}
	provision += "printf '%s\\n' '" + sourceDigest + "' > " + installerSourceMarkerPath + "\n"
	provision += "systemctl enable sshd.service\n"
	if !captureOnly {
		// SUSE's generator enables cloud-init.target; the stage units have
		// their own install hooks.
		provision += "systemctl enable cloud-init-local.service cloud-config.service cloud-final.service\ncloud-init clean --logs\n"
	}
	provision += "install -d -m 0755 " + path.Dir(tumbleweedSSHDOrdering) + "\nprintf '%s\\n' '[Unit]' 'After=systemd-user-sessions.service' > " + tumbleweedSSHDOrdering + "\n"
	// The credential writer leaves umask 077. The first boot fills this public
	// identity without changing its mode; unprivileged D-Bus must read it.
	provision += "rm -f /etc/machine-id\ninstall -m 0644 /dev/null /etc/machine-id\n"
	partitions, packages, loader := "", "", ""
	pinnedPackages := ""
	if !captureOnly {
		packages, pinnedPackages, err = tumbleweedSnapshotPackageSelection(release, version, architecture)
		if err != nil {
			return nil, err
		}
	}
	if captureOnly {
		for _, pkg := range release.Lab.InstallerPackages {
			packages += "<package>" + pkg + "</package>\n"
		}
		provision += "printf '%s\\n' 'repository-bootstrap-v1' > /etc/lindm-repository-bootstrap\n"
		provision += tumbleweedInstallerStage("provision-complete")
	}
	if passphrase != "" {
		loader = "<loader_type>grub2-bls</loader_type>"
		var escaped bytes.Buffer
		if err := xml.EscapeText(&escaped, []byte(passphrase)); err != nil {
			return nil, err
		}
		partitions = `<disklabel>gpt</disklabel><partitions config:type="list">
<partition><mount>/boot/efi</mount><filesystem config:type="symbol">vfat</filesystem><size>1G</size><partition_id config:type="integer">259</partition_id></partition>
<partition><mount>/boot</mount><filesystem config:type="symbol">ext4</filesystem><size>1G</size></partition>
<partition><mount>/</mount><filesystem config:type="symbol">btrfs</filesystem><size>max</size><crypt_fs config:type="boolean">true</crypt_fs><crypt_method config:type="symbol">luks2</crypt_method><crypt_key>` + escaped.String() + `</crypt_key></partition>
</partitions>`
		for _, pkg := range append(append([]string{}, release.Lab.Guest.Actions...), release.Lab.Session.Desktops[desktop]...) {
			packages += "<package>" + pkg + "</package>\n"
		}
		if tpmBoot {
			for _, pkg := range release.Lab.TPM.Packages {
				packages += "<package>" + pkg + "</package>\n"
			}
			provision += encryptedInstallerTPMProvision(release.Lab.TPM, architecture)
			provision += "sdbootutil --no-variables mkinitrd\n"
		}
		if desktop != "" {
			provision += encryptedInstallerDesktopProvision(release, desktop, architecture)
		}
	}
	provision += pinnedPackages
	target := "multi-user"
	if desktop != "" {
		target = "graphical"
	}
	// Base64 keeps credential bytes outside XML and shell token syntax.
	script := "printf '%s' '" + base64.StdEncoding.EncodeToString([]byte(provision)) + "' | base64 -d > /tmp/lindm-provision && /bin/sh -eu /tmp/lindm-provision && rm -f /tmp/lindm-provision\n"
	return []byte(fmt.Sprintf(`<?xml version="1.0"?>
<!DOCTYPE profile>
<profile xmlns="http://www.suse.com/1.0/yast2ns" xmlns:config="http://www.suse.com/1.0/configns">
  <general>
    <mode>
      <confirm config:type="boolean">false</confirm>
      <second_stage config:type="boolean">false</second_stage>
      <halt config:type="boolean">true</halt>
    </mode>
  </general>
  <report>
    <errors><show config:type="boolean">true</show><timeout config:type="integer">0</timeout><log config:type="boolean">true</log></errors>
    <warnings><show config:type="boolean">true</show><timeout config:type="integer">10</timeout><log config:type="boolean">true</log></warnings>
  </report>
  %[4]s
  <language><language>en_US</language></language>
  <keyboard><keymap>english-us</keymap></keyboard>
  <timezone><hwclock>UTC</hwclock><timezone>UTC</timezone></timezone>
  <networking>
    <keep_install_network config:type="boolean">true</keep_install_network>
  </networking>
  <partitioning config:type="list">
    <drive>
      <device>%[1]s</device>
      <initialize config:type="boolean">true</initialize>
      <use>all</use>
      %[6]s
    </drive>
  </partitioning>
  <bootloader>
    %[8]s
    <global>
      <append>net.ifnames=0 console=tty0 console=%[2]s</append>
      <terminal>console</terminal>
      <timeout config:type="integer">1</timeout>
      <update_nvram>false</update_nvram>
    </global>
  </bootloader>
  <software>
    <install_recommended config:type="boolean">%[11]s</install_recommended>
    <patterns config:type="list">
      <pattern>base</pattern>
      %[12]s
    </patterns>
    <packages config:type="list">
      <package>openssh-server</package>
      <package>sudo</package>
      %[5]s
      %[7]s
    </packages>
  </software>
  <services-manager>
    <default_target>%[10]s</default_target>
  </services-manager>
  <firewall>
    <enable_firewall config:type="boolean">true</enable_firewall>
    <start_firewall config:type="boolean">true</start_firewall>
    <default_zone>public</default_zone>
    <zones config:type="list">
      <zone>
        <name>public</name>
        <services config:type="list"><service>ssh</service><service>dhcpv6-client</service></services>
      </zone>
    </zones>
  </firewall>
  <users config:type="list">
    <user>
      <username>root</username>
      <user_password>!</user_password>
      <encrypted config:type="boolean">true</encrypted>
    </user>
    <user>
      <username>lindm-lab</username>
      <fullname>Lindm Lab</fullname>
      <home>/home/lindm-lab</home>
      <shell>/bin/bash</shell>
      <user_password>!</user_password>
      <encrypted config:type="boolean">true</encrypted>
    </user>
  </users>
  <scripts>
    %[9]s
    <chroot-scripts config:type="list">
      <script>
        <filename>lindm-provision</filename>
        <chrooted config:type="boolean">true</chrooted>
        <interpreter>shell</interpreter>
        <source><![CDATA[%[3]s]]></source>
      </script>
    </chroot-scripts>
  </scripts>
</profile>
`, disk, console, script, addOn, cloudPackages, partitions, packages, loader, preScript, target, recommended, enhancedBase)), nil
}

func tumbleweedInstallerRepository(snapshot *tumbleweedSnapshotRepository) (repository, preScript, provision string, err error) {
	if snapshot == nil {
		return "", "", "", errors.New("AutoYaST requires a retained signed repository snapshot")
	}
	u, err := url.Parse(snapshot.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(snapshot.CAPEM) == 0 {
		return "", "", "", errors.New("AutoYaST snapshot requires an HTTPS repository and its lab CA")
	}
	var escaped bytes.Buffer
	if err := xml.EscapeText(&escaped, []byte(snapshot.URL)); err != nil {
		return "", "", "", err
	}
	provision = "install -d -m 0755 /etc/pki/trust/anchors\n" +
		encryptedInstallerProvisionFile("/etc/pki/trust/anchors/lindm-snapshot.pem", string(snapshot.CAPEM)) +
		"update-ca-certificates\n"
	preScript = `<pre-scripts config:type="list"><script><filename>lindm-snapshot-trust</filename><interpreter>shell</interpreter><source><![CDATA[set -eu
` + provision + `]]></source></script></pre-scripts>`
	return escaped.String(), preScript, provision, nil
}

func tumbleweedInstallerStage(stage string) string {
	return "printf '\\n%s\\n' 'LINDM_INSTALLER_STAGE=" + stage + "' > /dev/console\n"
}

// AutoYaST's package list requests native package names. Exact snapshot EVRs
// are checked in the installed chroot, and again by the ordinary first-boot
// probe, so YaST cannot silently substitute a DVD kernel or a reduced flavor.
func tumbleweedSnapshotPackageSelection(release *platform.Release, version, architecture string) (packages, check string, err error) {
	if release == nil {
		return "", "", errors.New("final AutoYaST requires platform package facts")
	}
	pins := platform.RepositorySnapshotRecipes[release.ID].SnapshotPackages[version][architecture]
	if len(pins) == 0 {
		return "", "", fmt.Errorf("no exact AutoYaST package recipe for %s %s %s", release.ID, version, architecture)
	}
	for _, pin := range pins {
		name, evr, exact := strings.Cut(pin, "=")
		if !exact || name == "" || evr == "" {
			return "", "", errors.New("AutoYaST snapshot package requires an exact native EVR")
		}
		var escaped bytes.Buffer
		if err := xml.EscapeText(&escaped, []byte(name)); err != nil {
			return "", "", err
		}
		packages += "<package>" + escaped.String() + "</package>\n"
		if !strings.Contains(evr, ":") {
			evr = "0:" + evr
		}
		check += "test \"$(rpm -q --qf '%{EPOCHNUM}:%{VERSION}-%{RELEASE}\\n' -- " + nativeQuote(name) + ")\" = " + nativeQuote(evr) + "\n"
	}
	return packages, check, nil
}
