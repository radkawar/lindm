//go:build linux

package vmlab

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"

	"lindm/internal/platform"
)

const (
	provisionTestHost        = "lindm-console.test"
	provisionTestFingerprint = "0123456789ABCDEF0123456789ABCDEF01234567"
	provisionTestSecret      = "lpt_sensitive-provisioning-token"
)

// provisionTestInstallScript mirrors the console's enrollmentInstallScript
// (web/src/features/enrollment/snippets.ts) for an APT or RPM family.
func provisionTestInstallScript(family string) string {
	header := `(
set -eu
umask 077
. /etc/os-release
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
`
	verify := `curl --disable --fail --silent --show-error --proto '=https' --tlsv1.2 'https://lindm-console.test:18445/repository/key.asc' -o "$work/key.asc"
gpg --batch --with-colons --show-keys "$work/key.asc" > "$work/key-info"
test "$(awk -F: '$1 == "pub" { primary = 1; next } primary && $1 == "fpr" { print $10; primary = 0 }' "$work/key-info")" = '` + provisionTestFingerprint + `'
`
	trust := `
install -d -m 0755 /etc/lindm
install -m 0644 "$work/execution-root.json" /etc/lindm/execution-root.json
)`
	if family == "apt" {
		return header + "apt-get update\n" + verify + `install -d -m 0755 /etc/apt/keyrings
gpg --batch --yes --dearmor --output /etc/apt/keyrings/lindm.gpg "$work/key.asc"
printf '%s\n' 'Types: deb
URIs: https://lindm-console.test:18445/repository/apt
Suites: stable
Components: main
Signed-By: /etc/apt/keyrings/lindm.gpg' > /etc/apt/sources.list.d/lindm.sources
apt-get -y install lindm-agent` + trust
	}
	return header + "dnf -y install ca-certificates gnupg2 openssl\n" + verify + `printf '%s\n' '[lindm]
name=Lindm
baseurl=https://lindm-console.test:18445/repository/rpm
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/lindm' > /etc/yum.repos.d/lindm.repo
dnf -y install lindm-agent` + trust
}

const provisionTestPrerequisites = `# SENSITIVE BOOT INPUT: contains a reusable, bounded provisioning token.
# Deliver only to intended installations; never embed in a reusable/golden image.
`

const provisionTestUnit = `[Unit]
Description=Lindm first-boot provisioning and bounded approval resume
ConditionPathExists=/etc/lindm/provisioning-token

[Service]
Type=oneshot
ExecStart=/usr/libexec/lindm/lindm-agent resume -wait-seconds 3600
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target`

func indentLines(text, prefix string) string {
	lines := strings.Split(text, "\n")
	for i := range lines {
		lines[i] = prefix + lines[i]
	}
	return strings.Join(lines, "\n")
}

// provisionTestSnippet mirrors the console's provisioningSnippet shapes.
func provisionTestSnippet(t *testing.T, format, family string) []byte {
	t.Helper()
	install := provisionTestInstallScript(family)
	switch format {
	case "cloud-init":
		runcmd, err := json.Marshal("set -eu\n" + install + "\nsystemctl daemon-reload\nsystemctl enable --now lindm-executor.service lindm-agent.service\nsystemctl enable lindm-provision.service\nsystemctl start --no-block lindm-provision.service")
		if err != nil {
			t.Fatal(err)
		}
		return []byte("#cloud-config\n" + provisionTestPrerequisites + `write_files:
  - path: /etc/lindm/provisioning-token
    owner: root:root
    permissions: '0600'
    content: "` + provisionTestSecret + `"
  - path: /etc/systemd/system/lindm-provision.service
    owner: root:root
    permissions: '0644'
    content: |
` + indentLines(provisionTestUnit, "      ") + `
runcmd:
  - [sh, -c, ` + string(runcmd) + `]
`)
	case "autoinstall":
		// The user-data is the cloud-init body without its header comments.
		var body []string
		for line := range strings.SplitSeq(strings.TrimSuffix(string(provisionTestSnippet(t, "cloud-init", family)), "\n"), "\n") {
			if !strings.HasPrefix(line, "#") {
				body = append(body, line)
			}
		}
		return []byte("#cloud-config\n" + provisionTestPrerequisites + "# Merge these fields into the complete trusted autoinstall configuration.\nautoinstall:\n  version: 1\n  user-data:\n" + indentLines(strings.Join(body, "\n"), "    ") + "\n")
	case "kickstart", "autoyast":
		script := "set -eu\numask 077\n" + install + "\ninstall -d -m 0755 /etc/lindm\nbase64 -d > /etc/lindm/provisioning-token <<'LINDM_TOKEN'\nbHB0X3NlbnNpdGl2ZQ==\nLINDM_TOKEN\ncat > /etc/systemd/system/lindm-provision.service <<'LINDM_UNIT'\n" + provisionTestUnit + "\nLINDM_UNIT\nsystemctl enable lindm-executor.service lindm-agent.service lindm-provision.service"
		if format == "kickstart" {
			return []byte(provisionTestPrerequisites + "# Merge this %post section into the complete trusted Kickstart profile.\n%post --erroronfail --interpreter=/bin/sh\n" + script + "\n%end\n")
		}
		return []byte(`<?xml version="1.0"?>
<!-- SENSITIVE installer profile: reusable, bounded provisioning token. -->
<profile xmlns="http://www.suse.com/1.0/yast2ns" xmlns:config="http://www.suse.com/1.0/configns">
  <scripts>
    <chroot-scripts config:type="list">
      <script>
        <filename>lindm-enroll.sh</filename>
        <chrooted config:type="boolean">true</chrooted>
        <interpreter>shell</interpreter>
        <source><![CDATA[
` + script + `
]]></source>
      </script>
    </chroot-scripts>
  </scripts>
</profile>
`)
	}
	t.Fatalf("unknown format %s", format)
	return nil
}

func TestProvisionCloudInitSeedKeepsSnippetFirstAndVerbatim(t *testing.T) {
	snippet := provisionTestSnippet(t, "cloud-init", "apt")
	seed := &provisionSeed{snippet: snippet, host: provisionTestHost}
	config := map[string]any{"users": []any{map[string]any{"name": labUser}}, "ssh_pwauth": false}
	data, err := seed.userData(config)
	if err != nil {
		t.Fatal(err)
	}
	message, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	media, params, err := mime.ParseMediaType(message.Header.Get("Content-Type"))
	if err != nil || media != "multipart/mixed" || message.Header.Get("MIME-Version") != "1.0" {
		t.Fatalf("user-data is not a MIME multipart document: %q %v", media, err)
	}
	reader := multipart.NewReader(message.Body, params["boundary"])
	var parts [][]byte
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if part.Header.Get("Content-Type") != `text/cloud-config; charset="utf-8"` {
			t.Fatalf("part type %q", part.Header.Get("Content-Type"))
		}
		body, err := io.ReadAll(part)
		if err != nil {
			t.Fatal(err)
		}
		parts = append(parts, body)
	}
	if len(parts) != 2 || !bytes.Equal(parts[0], snippet) {
		t.Fatalf("snippet must be the exact first of two parts; got %d parts", len(parts))
	}
	lab, ok := bytes.CutPrefix(parts[1], []byte("#cloud-config\n"))
	if !ok {
		t.Fatal("lab part is not cloud-config")
	}
	var decoded struct {
		BootCmd  [][]string       `json:"bootcmd"`
		MergeHow []map[string]any `json:"merge_how"`
	}
	if err := json.Unmarshal(lab, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.BootCmd) != 1 || decoded.BootCmd[0][2] != provisionHostsCommand(provisionTestHost) {
		t.Fatalf("lab part must write the hosts line at boot: %v", decoded.BootCmd)
	}
	how, err := json.Marshal(decoded.MergeHow)
	if err != nil || string(how) != `[{"name":"list","settings":["append"]},{"name":"dict","settings":["no_replace","recurse_list"]}]` {
		t.Fatalf("lab part must append lists and never replace snippet keys: %s", how)
	}
	if bytes.Contains(parts[1], []byte(provisionTestSecret)) || seed.labPartsSHA256 == "" {
		t.Fatal("lab part must be scanned and must not carry snippet material")
	}
}

func TestProvisionCloudInitRefusesNonCloudConfigAndBoundaryCollision(t *testing.T) {
	lab := []byte("#cloud-config\n{}")
	if _, err := provisionCloudInitUserData([]byte("#!/bin/sh\n"), lab, "lindm-lab-0123456789abcdef"); err == nil {
		t.Fatal("shell script accepted as the cloud-init snippet")
	}
	if _, err := provisionCloudInitUserData([]byte("#cloud-config\n--lindm-lab-0123456789abcdef\n"), lab, "lindm-lab-0123456789abcdef"); err == nil {
		t.Fatal("boundary occurring in the snippet accepted")
	}
}

func TestProvisionAutoinstallKeepsSnippetBodyAndAppendsLabKeys(t *testing.T) {
	login, private, public := encryptedInstallerTestKeys(t)
	recipe, err := encryptedInstallerRecipeForMachine(labMedia("ubuntu"), "lab-passphrase", login, private, public, "", false, "aarch64")
	if err != nil {
		t.Fatal(err)
	}
	snippet := provisionTestSnippet(t, "autoinstall", "apt")
	merged, lab, err := provisionInstallerRecipe("autoinstall", recipe, snippet, provisionTestHost)
	if err != nil {
		t.Fatal(err)
	}
	_, body, _ := strings.Cut(string(snippet), "\nautoinstall:\n")
	if !strings.HasPrefix(string(merged), "#cloud-config\nautoinstall:\n"+body) {
		t.Fatal("merged autoinstall does not carry the snippet body verbatim first")
	}
	rest := strings.TrimPrefix(string(merged), "#cloud-config\nautoinstall:\n"+body)
	keys := map[string]json.RawMessage{}
	for line := range strings.SplitSeq(strings.TrimSuffix(rest, "\n"), "\n") {
		name, value, ok := strings.Cut(strings.TrimPrefix(line, "  "), ": ")
		var key string
		if !ok || !strings.HasPrefix(line, `  "`) || json.Unmarshal([]byte(name), &key) != nil || !json.Valid([]byte(value)) {
			t.Fatalf("lab key is not one JSON flow line: %q", line)
		}
		keys[key] = json.RawMessage(value)
	}
	if _, ok := keys["version"]; ok {
		t.Fatal("lab replaced the snippet's version")
	}
	if _, ok := keys["user-data"]; ok {
		t.Fatal("lab replaced the snippet's user-data")
	}
	var late [][]string
	if err := json.Unmarshal(keys["late-commands"], &late); err != nil || len(late) != 2 || late[1][len(late[1])-1] != provisionHostsCommand(provisionTestHost) {
		t.Fatalf("hosts line must be the lab's last late-command: %v", late)
	}
	if !strings.Contains(late[0][len(late[0])-1], "99-lindm-lab.cfg") {
		t.Fatal("lab late-command no longer writes the dropped user-data SSH settings")
	}
	if _, err := provisionLabPartsLindmFree(lab, provisionTestHost); err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(merged), "\n  version:") != 1 || strings.Count(string(merged), "\n  user-data:") != 1 {
		t.Fatal("snippet-owned keys duplicated")
	}
}

func TestProvisionAutoinstallRefusesForeignShapesAndKeyConflicts(t *testing.T) {
	lab := map[string]json.RawMessage{"late-commands": json.RawMessage(`[["true"]]`)}
	for name, snippet := range map[string]string{
		"top-level key": "#cloud-config\nruncmd: [true]\nautoinstall:\n  version: 1\n  user-data: {}\n",
		"no key":        "#cloud-config\n# nothing\n",
		"unindented":    "#cloud-config\nautoinstall:\n  version: 1\n  user-data: {}\nruncmd: []\n",
		"conflict":      "#cloud-config\nautoinstall:\n  version: 1\n  user-data: {}\n  late-commands: []\n",
		"no user-data":  "#cloud-config\nautoinstall:\n  version: 1\n",
	} {
		if _, err := mergeAutoinstall([]byte(snippet), lab); err == nil {
			t.Fatalf("%s: autoinstall snippet accepted", name)
		}
	}
}

func TestProvisionKickstartAppendsSnippetAfterEveryLabSection(t *testing.T) {
	login, private, public := encryptedInstallerTestKeys(t)
	// RHEL installs only from its DVD and keeps no enabled repository: the lab
	// adds none, so the snippet alone must reach the lindm repository.
	for _, distribution := range []string{"fedora", "rhel"} {
		recipe, err := encryptedInstallerRecipeForMachine(labMedia(distribution), "lab-passphrase", login, private, public, "", false, "aarch64")
		if err != nil {
			t.Fatal(err)
		}
		snippet := provisionTestSnippet(t, "kickstart", "rpm")
		merged, lab, err := provisionInstallerRecipe("kickstart", recipe, snippet, provisionTestHost)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.HasPrefix(merged, recipe) || !bytes.HasSuffix(merged, snippet) || !bytes.Equal(merged, append(append([]byte{}, lab...), snippet...)) {
			t.Fatalf("%s: kickstart must be lab recipe, lab sections, then the verbatim snippet", distribution)
		}
		sections := string(lab[len(recipe):])
		if sections != "%post --erroronfail --interpreter=/bin/sh\nset -eu\n"+provisionHostsCommand(provisionTestHost)+"\n%end\n" {
			t.Fatalf("%s: the only lab section must write the hosts line: %q", distribution, sections)
		}
		if _, err := provisionLabPartsLindmFree(lab, provisionTestHost); err != nil {
			t.Fatalf("%s: %v", distribution, err)
		}
	}
	if _, err := appendKickstart([]byte("text\n%end\n"), nil, []byte("rootpw --plaintext x\n%post\ntrue\n%end\n")); err == nil {
		t.Fatal("kickstart snippet with commands before its post section accepted")
	}
	if _, err := appendKickstart([]byte("text\n%end\n"), nil, []byte("# no section\n")); err == nil {
		t.Fatal("kickstart snippet without a post section accepted")
	}
}

func TestProvisionAutoYaSTSplicesSnippetScriptsLast(t *testing.T) {
	login, private, public := encryptedInstallerTestKeys(t)
	release := platform.ForManifest("opensuse-tumbleweed", "20261007")
	recipe, err := tumbleweedInstallerRecipeWithEncryption(release, "20261007", "/dev/vda", "aarch64", strings.Repeat("a", 64), login, private, public, "lab-passphrase", "", false, &tumbleweedSnapshotRepository{URL: tumbleweedTestRepository, CAPEM: []byte("test-only CA")})
	if err != nil {
		t.Fatal(err)
	}
	snippet := provisionTestSnippet(t, "autoyast", "zypper")
	merged, lab, err := provisionInstallerRecipe("autoyast", recipe, snippet, provisionTestHost)
	if err != nil {
		t.Fatal(err)
	}
	start := bytes.Index(snippet, []byte(autoyastChrootOpen)) + len(autoyastChrootOpen)
	inner := snippet[start : start+bytes.Index(snippet[start:], []byte(autoyastChrootClose))]
	if bytes.Count(merged, []byte(autoyastChrootOpen)) != 1 || !bytes.Contains(merged, append(append([]byte{}, inner...), []byte(autoyastChrootClose)...)) {
		t.Fatal("snippet scripts must be spliced verbatim at the end of the one chroot-scripts list")
	}
	labScript, hosts, snippetScript := bytes.Index(merged, []byte("<filename>lindm-provision</filename>")), bytes.Index(merged, []byte("<filename>lab-hosts</filename>")), bytes.Index(merged, inner)
	if labScript < 0 || hosts < labScript || snippetScript < hosts {
		t.Fatal("lab chroot-scripts must run before the snippet's")
	}
	if err := xmlWellFormed(merged); err != nil {
		t.Fatal(err)
	}
	var profile struct {
		Scripts []struct {
			Filename string `xml:"filename"`
			Chrooted bool   `xml:"chrooted"`
		} `xml:"scripts>chroot-scripts>script"`
	}
	if err := xml.Unmarshal(merged, &profile); err != nil || len(profile.Scripts) < 3 || !profile.Scripts[len(profile.Scripts)-1].Chrooted {
		t.Fatalf("merged profile scripts: %+v %v", profile.Scripts, err)
	}
	if _, err := provisionLabPartsLindmFree(lab, provisionTestHost); err != nil {
		t.Fatal(err)
	}
	created, err := spliceAutoYaSTItems([]byte("<profile><general/></profile>"), []byte("<script/>"))
	if err != nil || !bytes.Contains(created, []byte("<scripts>"+autoyastChrootOpen+"<script/>"+autoyastChrootClose+"</scripts>")) {
		t.Fatalf("absent chroot-scripts list was not created: %s %v", created, err)
	}
	extra := bytes.Replace(snippet, []byte("<scripts>"), []byte("<software/><scripts>"), 1)
	if _, err := spliceAutoYaST(recipe, nil, extra); err == nil {
		t.Fatal("snippet section outside chroot-scripts silently dropped")
	}
}

func TestProvisionLabPartsRefuseLindmInputs(t *testing.T) {
	encode := base64.StdEncoding.EncodeToString
	hidden := "printf '%s' '" + encode([]byte("install -d /etc/lindm/\n")) + "' | base64 -d > /tmp/x\n"
	nested := "printf '%s' '" + encode([]byte(hidden)) + "' | base64 -d > /tmp/y\n"
	for name, lab := range map[string]string{
		"plain":        "dnf install lindm-agent\n",
		"nested":       nested,
		"origin":       "curl https://" + provisionTestHost + ":1/\n",
		"json escaped": "#cloud-config\n" + `{"runcmd":[["sh","-c","ls \u002fetc\u002flindm\u002f"]]}`,
	} {
		if _, err := provisionLabPartsLindmFree([]byte(lab), provisionTestHost); err == nil {
			t.Fatalf("%s: lab part carrying lindm input accepted", name)
		}
	}
	if _, err := provisionLabPartsLindmFree([]byte(provisionHostsCommand(provisionTestHost)+"\n/etc/lindm-lab-installer-source\n"), provisionTestHost); err != nil {
		t.Fatalf("hosts line and lab-owned paths refused: %v", err)
	}
}

func TestProvisionSnippetPinsComeFromTheSnippet(t *testing.T) {
	for _, tc := range []struct {
		format, family string
		backend        platform.Backend
		repository     string
	}{
		{"cloud-init", "apt", platform.BackendAPT, "https://lindm-console.test:18445/repository/apt"},
		{"autoinstall", "apt", platform.BackendAPT, "https://lindm-console.test:18445/repository/apt"},
		{"kickstart", "rpm", platform.BackendDNF5, "https://lindm-console.test:18445/repository/rpm"},
		{"cloud-init", "rpm", platform.BackendDNF4, "https://lindm-console.test:18445/repository/rpm"},
	} {
		pins, err := provisionSnippetPins(provisionTestSnippet(t, tc.format, tc.family), tc.backend, provisionTestHost)
		if err != nil || pins.Fingerprint != provisionTestFingerprint || pins.Repository != tc.repository {
			t.Fatalf("%s/%s pins %+v %v", tc.format, tc.family, pins, err)
		}
	}
	if _, err := provisionSnippetPins(provisionTestSnippet(t, "kickstart", "rpm"), platform.BackendDNF5, "other.test"); err == nil {
		t.Fatal("repository off the origin host accepted")
	}
}

func TestProvisionGuestOutputParsers(t *testing.T) {
	policy := `lindm-agent:
  Installed: 0.1.0
  Candidate: 0.1.0
  Version table:
 *** 0.1.0 500
        500 https://lindm-console.test:18445/repository/apt stable/main arm64 Packages
        100 /var/lib/dpkg/status
     0.0.9 500
        500 https://other.test/apt stable/main arm64 Packages
`
	if got := aptPolicyOrigins(policy); len(got) != 1 || got[0] != "https://lindm-console.test:18445/repository/apt" {
		t.Fatalf("installed version origins: %v", got)
	}
	colons := "pub:-:4096:1:89ABCDEF01234567:1700000000:::-:::scESC::::::23::0:\nfpr:::::::::" + provisionTestFingerprint + ":\nuid:-::::1700000000::X::lindm::::::::::0:\nsub:-:4096:1:1111111111111111:1700000000::::::e::::::23:\nfpr:::::::::FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:\n"
	if got := gpgPrimaryFingerprints(colons); len(got) != 1 || got[0] != provisionTestFingerprint {
		t.Fatalf("primary fingerprints: %v", got)
	}
	if got := rpmSignatureKeyIDs("RSA/SHA256, Mon 12 Oct 2026, Key ID 89abcdef01234567|(none)|(none)|(none)\n"); len(got) != 1 || !strings.HasSuffix(provisionTestFingerprint, got[0]) {
		t.Fatalf("rpm signer key IDs: %v", got)
	}
}
