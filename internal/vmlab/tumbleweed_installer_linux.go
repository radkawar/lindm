//go:build linux

package vmlab

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/platform"
)

// tumbleweedInstallerEdition names signed openSUSE Tumbleweed snapshot DVD
// media. The DVD carries the installation repository for exactly one snapshot,
// so the base system is pinned by the authenticated ISO digest. The DVD lacks
// cloud-init; only that closure comes from the official online repository,
// which tumbleweedRepositorySnapshot binds to the same signed snapshot.
const tumbleweedInstallerEdition = "dvd"

// Bump when the AutoYaST profile or machine layout changes.
const tumbleweedInstallerRecipeVersion = "opensuse-tumbleweed-dvd-autoyast-v2"

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
	if release.Lab.Installer != platform.AutoYaST || m.GetEdition() != tumbleweedInstallerEdition || m.GetRelease() != "Snapshot"+m.GetVersion() ||
		m.GetImageFilename() != "openSUSE-Tumbleweed-DVD-"+architecture+"-Snapshot"+m.GetVersion()+"-Media.iso" ||
		m.GetChecksumMode() != labv1.ChecksumMode_CHECKSUM_MODE_DETACHED {
		return nil, errors.New("tumbleweed installed image requires a signed snapshot-pinned Tumbleweed DVD manifest")
	}
	version := m.GetVersion()
	return &installerImage{
		label:     "tumbleweed",
		installer: platform.AutoYaST,
		cache:     "tumbleweed-installed",
		version:   tumbleweedInstallerRecipeVersion,
		// YaST resolves the full DVD repository in memory.
		memoryMiB: 4096,
		recipe:    tumbleweedInstallerRecipe,
		bindSources: func(ctx context.Context, root *os.Root, staging, phase string) error {
			return tumbleweedRepositorySnapshot(ctx, m, root, staging, phase)
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

// tumbleweedRepository is the official online OSS tree; aarch64 is published
// under ports. The download.opensuse.org origin serves signed metadata itself.
func tumbleweedRepository(architecture string) string {
	if architecture == "aarch64" {
		return "https://download.opensuse.org/ports/aarch64/tumbleweed/repo/oss/"
	}
	return "https://download.opensuse.org/tumbleweed/repo/oss/"
}

// tumbleweedRepositorySnapshot requires the online repository's repomd.xml,
// signed by the manifest's pinned key, to name the manifest snapshot. It runs
// before and after installation: published snapshots only advance, so equal
// signed snapshots on both sides bound the metadata libzypp resolved between
// them. A moved repository fails closed; bump the manifest to its new DVD.
func tumbleweedRepositorySnapshot(ctx context.Context, m *labv1.ImageManifest, root *os.Root, staging, phase string) error {
	architecture, _, err := encryptedInstallerArchitecture(m.GetArchitecture())
	if err != nil {
		return err
	}
	if phase != "before" && phase != "after" {
		return errors.New("tumbleweed repository binding requires a known phase")
	}
	client := (Fetcher{}).client()
	defer client.CloseIdleConnections()
	base := tumbleweedRepository(architecture)
	files := make(map[string][]byte, 3)
	for _, source := range []struct{ name, url string }{
		{"repomd.xml", base + "repodata/repomd.xml"},
		{"repomd.xml.asc", base + "repodata/repomd.xml.asc"},
		{"key", m.GetKeyUrl()},
	} {
		name := staging + "/repository-" + phase + "-" + source.name
		if err := download(ctx, client, root, name, source.url, maxMetadataBytes, 2*time.Minute); err != nil {
			return fmt.Errorf("tumbleweed repository %s: %w", phase, err)
		}
		if files[source.name], err = readCacheFile(root, name, maxMetadataBytes); err != nil {
			return err
		}
	}
	_, _, metadata, err := verifySignedBytes(ctx, m.GetSignerFingerprint(), false, files["repomd.xml"], files["repomd.xml.asc"], files["key"])
	if err != nil {
		return fmt.Errorf("tumbleweed repository %s: %w", phase, err)
	}
	snapshot, err := tumbleweedRepositoryDistro(metadata)
	if err != nil {
		return err
	}
	if snapshot != m.GetVersion() {
		return fmt.Errorf("tumbleweed repository %s installation is snapshot %s, not pinned %s", phase, snapshot, m.GetVersion())
	}
	return nil
}

// tumbleweedRepositoryDistro returns the snapshot of the single distro tag in
// signed repomd.xml, for example cpe:/o:opensuse:opensuse:20261007.
func tumbleweedRepositoryDistro(metadata []byte) (string, error) {
	var repomd struct {
		Distros []struct {
			CPE  string `xml:"cpeid,attr"`
			Name string `xml:",chardata"`
		} `xml:"tags>distro"`
	}
	if err := xml.Unmarshal(metadata, &repomd); err != nil {
		return "", fmt.Errorf("tumbleweed repository metadata: %w", err)
	}
	if len(repomd.Distros) != 1 {
		return "", errors.New("tumbleweed repository metadata must name exactly one distribution")
	}
	snapshot, ok := strings.CutPrefix(repomd.Distros[0].CPE, "cpe:/o:opensuse:opensuse:")
	if _, err := time.Parse("20060102", snapshot); !ok || err != nil || len(snapshot) != 8 || strings.TrimSpace(repomd.Distros[0].Name) != "openSUSE Tumbleweed "+snapshot {
		return "", errors.New("tumbleweed repository metadata names no dated snapshot")
	}
	return snapshot, nil
}

// tumbleweedInstallerRecipe returns an AutoYaST profile. The vendor guided
// proposal partitions the owned disk (Btrfs root, as on a default install).
// The DVD repository outranks the snapshot-bound online repository, which only
// supplies packages the DVD lacks. YaST installs the bootloader to the
// removable path without touching firmware variables, because every later
// guest starts from fresh pinned variables.
func tumbleweedInstallerRecipe(disk, architecture, sourceDigest, login, hostPrivate, hostPublic string) ([]byte, error) {
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
	provision := "set -eu\n" + encryptedInstallerProvision(login, hostPrivate, hostPublic)
	provision += "install -d -m 0755 /etc/cloud/cloud.cfg.d\nprintf '%s\\n' 'datasource_list: [ NoCloud ]' 'network: {config: disabled}' > /etc/cloud/cloud.cfg.d/99-lindm-lab.cfg\n"
	provision += "printf '%s\\n' '" + sourceDigest + "' > " + installerSourceMarkerPath + "\n"
	// SUSE's cloud-init.service has no [Install]; its generator enables
	// cloud-init.target, which wants these stage units.
	provision += "systemctl enable sshd.service cloud-init-local.service cloud-config.service cloud-final.service\n"
	provision += "install -d -m 0755 " + path.Dir(tumbleweedSSHDOrdering) + "\nprintf '%s\\n' '[Unit]' 'After=systemd-user-sessions.service' > " + tumbleweedSSHDOrdering + "\n"
	provision += "cloud-init clean --logs\nrm -f /etc/machine-id\ntouch /etc/machine-id\n"
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
  <add-on>
    <add_on_others config:type="list">
      <listentry>
        <media_url>%[4]s</media_url>
        <alias>%[5]s</alias>
        <name>openSUSE Tumbleweed OSS (snapshot-bound)</name>
        <priority config:type="integer">120</priority>
        <ask_on_error config:type="boolean">false</ask_on_error>
      </listentry>
    </add_on_others>
  </add-on>
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
    </drive>
  </partitioning>
  <bootloader>
    <global>
      <append>net.ifnames=0 console=tty0 console=%[2]s</append>
      <terminal>console</terminal>
      <timeout config:type="integer">1</timeout>
      <update_nvram>false</update_nvram>
    </global>
  </bootloader>
  <software>
    <install_recommended config:type="boolean">true</install_recommended>
    <patterns config:type="list">
      <pattern>base</pattern>
      <pattern>enhanced_base</pattern>
    </patterns>
    <packages config:type="list">
      <package>openssh-server</package>
      <package>sudo</package>
      <package>cloud-init</package>
      <package>cloud-init-config-suse</package>
    </packages>
  </software>
  <services-manager>
    <default_target>multi-user</default_target>
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
`, disk, console, script, tumbleweedRepository(architecture), tumbleweedRepositoryAlias)), nil
}
