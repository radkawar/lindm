// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"

	"lindm/internal/packaging"
	"lindm/internal/platform"
)

// The provisioning lanes feed a console snippet verbatim into a vendor
// unattended install. These pure functions are the only permitted lab merges:
// lab-owned parts always run before the snippet and never replace its keys.

// provisionHostAddress is QEMU user networking's host: the guest reaches the
// fixture's host-loopback listeners (or a lab host's reverse forwards) there.
const provisionHostAddress = "10.0.2.2"

// provisionHostsLine maps the origin hostname to the QEMU host.
func provisionHostsLine(host string) string { return provisionHostAddress + " " + host }

// provisionHostsCommand idempotently adds the lab-owned /etc/hosts line. The
// host is a validated hostname, so single quotes cannot be escaped from.
func provisionHostsCommand(host string) string {
	line := provisionHostsLine(host)
	return "grep -qxF '" + line + "' /etc/hosts || echo '" + line + "' >> /etc/hosts"
}

// cloudInitMergeHow makes every lab list append and never replace a snippet key.
var cloudInitMergeHow = []any{
	map[string]any{"name": "list", "settings": []string{"append"}},
	map[string]any{"name": "dict", "settings": []string{"no_replace", "recurse_list"}},
}

// provisionCloudInitUserData returns MIME multipart user-data: the snippet
// bytes verbatim first, then the lab access cloud-config, which merges with
// cloudInitMergeHow. Parts use LF line ends; the separator before each
// boundary belongs to the delimiter, so part bodies are exact.
func provisionCloudInitUserData(snippet, lab []byte, boundary string) ([]byte, error) {
	if !bytes.HasPrefix(snippet, []byte("#cloud-config\n")) || !bytes.HasPrefix(lab, []byte("#cloud-config\n")) {
		return nil, errors.New("cloud-init provisioning parts must be #cloud-config documents")
	}
	if len(boundary) < 16 || len(boundary) > 70 || strings.Trim(boundary, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" {
		return nil, errors.New("cloud-init multipart boundary must be a random token")
	}
	delimiter := []byte("--" + boundary)
	if bytes.Contains(snippet, delimiter) || bytes.Contains(lab, delimiter) {
		return nil, errors.New("cloud-init multipart boundary occurs in a part")
	}
	var out bytes.Buffer
	out.WriteString("Content-Type: multipart/mixed; boundary=\"" + boundary + "\"\nMIME-Version: 1.0\n")
	for _, part := range []struct {
		name string
		body []byte
	}{{"lindm-provisioning.cfg", snippet}, {"lab-access.cfg", lab}} {
		out.WriteString("\n--" + boundary + "\nContent-Type: text/cloud-config; charset=\"utf-8\"\nContent-Transfer-Encoding: 8bit\nContent-Disposition: attachment; filename=\"" + part.name + "\"\n\n")
		out.Write(part.body)
	}
	out.WriteString("\n--" + boundary + "--\n")
	return out.Bytes(), nil
}

// provisionSeed is the cloud-init lane's NoCloud seed: the console snippet
// plus the lab's access cloud-config, which also writes the hosts line.
type provisionSeed struct {
	snippet []byte
	host    string
	// labPartsSHA256 binds the lab-owned part admitted by the lindm-free scan.
	labPartsSHA256 string
}

var _ guestUserData = (*provisionSeed)(nil)

func (s *provisionSeed) userData(config map[string]any) ([]byte, error) {
	commands, _ := config["bootcmd"].([]any) // absent or foreign-typed bootcmd starts empty.
	config["bootcmd"] = append(commands, []string{"sh", "-c", provisionHostsCommand(s.host)})
	config["merge_how"] = cloudInitMergeHow
	lab, err := labCloudConfig(config)
	if err != nil {
		return nil, err
	}
	defer clear(lab)
	if s.labPartsSHA256, err = provisionLabPartsLindmFree(lab, s.host); err != nil {
		return nil, err
	}
	token := make([]byte, 16)
	if _, err := rand.Read(token); err != nil {
		return nil, err
	}
	return provisionCloudInitUserData(s.snippet, lab, "lindm-lab-"+hex.EncodeToString(token))
}

// mergeAutoinstall emits #cloud-config, the autoinstall key, every snippet
// line after its column-0 `autoinstall:` line verbatim, then each lab key as
// one `  "key": <JSON>` line. The snippet owns version and user-data.
func mergeAutoinstall(snippet []byte, lab map[string]json.RawMessage) ([]byte, error) {
	lines := strings.SplitAfter(string(snippet), "\n")
	start := -1
	for i, line := range lines {
		if line == "autoinstall:\n" {
			start = i + 1
			break
		}
		if trimmed := strings.TrimSpace(line); trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			return nil, errors.New("autoinstall snippet has content outside its autoinstall key")
		}
	}
	if start < 0 || start == len(lines) {
		return nil, errors.New("autoinstall snippet lacks a column-0 autoinstall: line")
	}
	snippetKeys := map[string]bool{}
	for _, line := range lines[start:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !strings.HasPrefix(line, " ") {
			return nil, errors.New("autoinstall snippet has an unindented line inside its autoinstall mapping")
		}
		if key, _, ok := strings.Cut(strings.TrimPrefix(line, "  "), ":"); ok && !strings.HasPrefix(line, "   ") {
			snippetKeys[key] = true
		}
	}
	if !snippetKeys["version"] || !snippetKeys["user-data"] {
		return nil, errors.New("autoinstall snippet must own version and user-data")
	}
	body := strings.Join(lines[start:], "")
	if !strings.HasSuffix(body, "\n") {
		body += "\n"
	}
	var out bytes.Buffer
	out.WriteString("#cloud-config\nautoinstall:\n")
	out.WriteString(body)
	keys := make([]string, 0, len(lab))
	for key := range lab {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		if key == "version" || key == "user-data" || snippetKeys[key] {
			return nil, fmt.Errorf("lab autoinstall key %q would replace a snippet key", key)
		}
		var value bytes.Buffer
		if err := json.Compact(&value, lab[key]); err != nil {
			return nil, fmt.Errorf("lab autoinstall key %q is not JSON", key)
		}
		name, err := json.Marshal(key)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&out, "  %s: %s\n", name, value.Bytes())
	}
	return out.Bytes(), nil
}

// labAutoinstall decodes the lab's own autoinstall recipe (#cloud-config plus
// a JSON document), drops the keys the snippet owns and appends lab late
// commands after the recipe's own.
func labAutoinstall(recipe []byte, lateCommands ...[]string) (map[string]json.RawMessage, error) {
	document, ok := bytes.CutPrefix(recipe, []byte("#cloud-config\n"))
	if !ok {
		return nil, errors.New("lab autoinstall recipe is not a cloud-config document")
	}
	var outer map[string]json.RawMessage
	if err := json.Unmarshal(document, &outer); err != nil || len(outer) != 1 || outer["autoinstall"] == nil {
		return nil, errors.New("lab autoinstall recipe must hold only the autoinstall key")
	}
	var lab map[string]json.RawMessage
	if err := json.Unmarshal(outer["autoinstall"], &lab); err != nil {
		return nil, errors.New("lab autoinstall section is not a JSON object")
	}
	// The snippet owns these; the lab's SSH settings already reach the
	// installed system through its late-command (99-lindm-lab.cfg).
	delete(lab, "version")
	delete(lab, "user-data")
	var late [][]string
	if err := json.Unmarshal(lab["late-commands"], &late); err != nil || len(late) == 0 {
		return nil, errors.New("lab autoinstall recipe lacks its late-commands")
	}
	data, err := json.Marshal(append(late, lateCommands...))
	if err != nil {
		return nil, err
	}
	lab["late-commands"] = data
	return lab, nil
}

// appendKickstart appends the snippet verbatim after the complete lab
// kickstart and its extra lab sections, so every lab %post runs first.
func appendKickstart(lab, labSections, snippet []byte) ([]byte, error) {
	if !bytes.HasSuffix(lab, []byte("%end\n")) || (len(labSections) != 0 && !bytes.HasSuffix(labSections, []byte("%end\n"))) {
		return nil, errors.New("lab kickstart parts must end with a complete section")
	}
	post := 0
	if !bytes.HasPrefix(snippet, []byte("%post")) {
		if post = bytes.Index(snippet, []byte("\n%post")) + 1; post == 0 {
			return nil, errors.New("kickstart snippet must hold a %post section")
		}
	}
	if !bytes.Contains(snippet[post:], []byte("\n%end\n")) {
		return nil, errors.New("kickstart snippet must hold a complete %post section")
	}
	for line := range strings.SplitSeq(string(snippet[:post]), "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			return nil, errors.New("kickstart snippet has commands before its %post section")
		}
	}
	return slices.Concat(lab, labSections, snippet), nil
}

const (
	autoyastChrootOpen  = `<chroot-scripts config:type="list">`
	autoyastChrootClose = `</chroot-scripts>`
)

// spliceAutoYaST inserts the lab scripts, then the snippet's exact bytes
// between its chroot-scripts tags, at the end of the lab profile's
// chroot-scripts list (created when absent). The snippet may hold no other
// profile section, so nothing it carries is silently dropped.
func spliceAutoYaST(lab, labScripts, snippet []byte) ([]byte, error) {
	open := bytes.Index(snippet, []byte(autoyastChrootOpen))
	if open < 0 || bytes.Count(snippet, []byte(autoyastChrootOpen)) != 1 {
		return nil, errors.New("autoyast snippet must hold exactly one chroot-scripts list")
	}
	inner := snippet[open+len(autoyastChrootOpen):]
	end := bytes.Index(inner, []byte(autoyastChrootClose))
	if end < 0 {
		return nil, errors.New("autoyast snippet chroot-scripts list is not closed")
	}
	inner = inner[:end]
	skeleton := slices.Concat(snippet[:open], snippet[open+len(autoyastChrootOpen)+end+len(autoyastChrootClose):])
	if err := autoyastOnlyScripts(skeleton); err != nil {
		return nil, err
	}
	return spliceAutoYaSTItems(lab, slices.Concat(labScripts, inner))
}

// spliceAutoYaSTItems appends script items to the end of the lab profile's
// chroot-scripts list, creating the list when absent.
func spliceAutoYaSTItems(lab, addition []byte) ([]byte, error) {
	if bytes.Count(lab, []byte(autoyastChrootOpen)) > 1 || bytes.Count(lab, []byte("</profile>")) != 1 {
		return nil, errors.New("lab autoyast profile must hold one profile and at most one chroot-scripts list")
	}
	var out []byte
	switch open := bytes.Index(lab, []byte(autoyastChrootOpen)); {
	case open >= 0:
		at := bytes.Index(lab[open:], []byte(autoyastChrootClose))
		if at < 0 {
			return nil, errors.New("lab chroot-scripts list is not closed")
		}
		at += open
		out = slices.Concat(lab[:at], addition, lab[at:])
	case bytes.Count(lab, []byte("</scripts>")) == 1:
		at := bytes.Index(lab, []byte("</scripts>"))
		out = slices.Concat(lab[:at], []byte(autoyastChrootOpen), addition, []byte(autoyastChrootClose+"\n"), lab[at:])
	default:
		at := bytes.Index(lab, []byte("</profile>"))
		out = slices.Concat(lab[:at], []byte("<scripts>"+autoyastChrootOpen), addition, []byte(autoyastChrootClose+"</scripts>\n"), lab[at:])
	}
	if err := xmlWellFormed(out); err != nil {
		return nil, fmt.Errorf("merged autoyast profile: %w", err)
	}
	return out, nil
}

// autoyastOnlyScripts accepts a snippet skeleton holding only the profile and
// scripts wrappers (the chroot-scripts content already removed).
func autoyastOnlyScripts(skeleton []byte) error {
	decoder := xml.NewDecoder(bytes.NewReader(skeleton))
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return errors.New("autoyast snippet is not well-formed XML")
		}
		switch t := token.(type) {
		case xml.StartElement:
			if t.Name.Local != "profile" && t.Name.Local != "scripts" {
				return fmt.Errorf("autoyast snippet carries unmerged section %q", t.Name.Local)
			}
		case xml.CharData:
			if len(bytes.TrimSpace(t)) != 0 {
				return errors.New("autoyast snippet carries text outside its scripts")
			}
		}
	}
}

func xmlWellFormed(document []byte) error {
	decoder := xml.NewDecoder(bytes.NewReader(document))
	for {
		if _, err := decoder.Token(); errors.Is(err, io.EOF) {
			return nil
		} else if err != nil {
			return errors.New("not well-formed XML")
		}
	}
}

// autoyastLabScript is a lab chroot-script item; source is CDATA-safe shell.
func autoyastLabScript(filename, source string) ([]byte, error) {
	if strings.Contains(source, "]]>") {
		return nil, errors.New("autoyast lab script cannot hold a CDATA terminator")
	}
	return []byte("      <script>\n        <filename>" + filename + "</filename>\n        <chrooted config:type=\"boolean\">true</chrooted>\n        <interpreter>shell</interpreter>\n        <source><![CDATA[set -eu\n" + source + "\n]]></source>\n      </script>\n"), nil
}

// provisionLindmMarkers name lindm agent, repository, trust and enrollment
// inputs. None may appear in a lab-owned part: the snippet is the only lindm
// input of a provisioning lane.
var provisionLindmMarkers = []string{packaging.BinaryPath, "lindm-agent", "lindm-executor", "lindm-provision.service", "/etc/lindm/", "/var/lib/lindm/", "keyrings/lindm", "lindm.sources", "lindm.list", "lindm.repo", "rpm-gpg/lindm", "lindm.crt", "provisioning-token", "bootstrap.dsse", "execution-root"}

var provisionEmbeddedBase64 = regexp.MustCompile(`printf '%s' '([A-Za-z0-9+/=]+)' \| base64 -d`)

// provisionLabPartsLindmFree scans lab-owned bytes, JSON-decoded strings and
// base64 payloads the lab embeds, for lindm inputs. The origin hostname may
// occur only in the lab's hosts line. It returns the parts' SHA-256.
func provisionLabPartsLindmFree(lab []byte, host string) (string, error) {
	text := []string{string(lab)}
	if document, ok := bytes.CutPrefix(lab, []byte("#cloud-config\n")); ok {
		var decoded any
		if err := json.Unmarshal(document, &decoded); err != nil {
			return "", errors.New("lab cloud-config part is not JSON")
		}
		text = appendJSONStrings(text, decoded)
	}
	// Lab recipes nest base64 file payloads inside base64 scripts; decode
	// each newly found layer, to a fixed depth.
	pending := text
	for range 4 {
		var nested []string
		for _, value := range pending {
			for _, match := range provisionEmbeddedBase64.FindAllStringSubmatch(value, -1) {
				data, err := base64.StdEncoding.DecodeString(match[1])
				if err != nil {
					return "", errors.New("lab part embeds an invalid base64 payload")
				}
				nested = append(nested, string(data))
			}
		}
		if len(nested) == 0 {
			break
		}
		text, pending = slices.Concat(text, nested), nested
	}
	for _, value := range text {
		for _, marker := range provisionLindmMarkers {
			if strings.Contains(value, marker) {
				return "", fmt.Errorf("lab-owned provisioning part carries lindm input %q", marker)
			}
		}
		if strings.Contains(strings.ReplaceAll(value, provisionHostsLine(host), ""), host) {
			return "", errors.New("lab-owned provisioning part names the lindm origin outside its hosts line")
		}
	}
	digest := sha256.Sum256(lab)
	return hex.EncodeToString(digest[:]), nil
}

func appendJSONStrings(out []string, value any) []string {
	switch v := value.(type) {
	case string:
		return append(out, v)
	case []any:
		for _, item := range v {
			out = appendJSONStrings(out, item)
		}
	case map[string]any:
		for key, item := range v {
			out = appendJSONStrings(append(out, key), item)
		}
	}
	return out
}

// provisionPins are the snippet's own trust pins, re-observed on the guest.
type provisionPins struct {
	Fingerprint string `json:"signing_key_fingerprint"`
	Repository  string `json:"repository"`
}

var (
	provisionPinnedFingerprint = regexp.MustCompile(`key-info\\?"\)\\?" = '([0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})'`)
	provisionAPTRepository     = regexp.MustCompile(`URIs: (https://[^\s'"\\]+)`)
	provisionRPMRepository     = regexp.MustCompile(`baseurl=(https://[^\s'"\\]+)`)
)

// provisionSnippetPins extracts the pinned signing-key fingerprint and the
// repository URL from the snippet; the repository must be on the origin host.
func provisionSnippetPins(snippet []byte, backend platform.Backend, host string) (provisionPins, error) {
	var pins provisionPins
	fingerprints := provisionPinnedFingerprint.FindAllSubmatch(snippet, -1)
	if len(fingerprints) != 1 {
		return pins, errors.New("snippet must pin exactly one repository signing-key fingerprint")
	}
	pins.Fingerprint = strings.ToUpper(string(fingerprints[0][1]))
	pattern := provisionRPMRepository
	if backend == platform.BackendAPT {
		pattern = provisionAPTRepository
	}
	repositories := pattern.FindAllSubmatch(snippet, -1)
	if len(repositories) != 1 {
		return pins, errors.New("snippet must configure exactly one lindm repository")
	}
	pins.Repository = string(repositories[0][1])
	if !strings.HasPrefix(pins.Repository, "https://"+host+":") && !strings.HasPrefix(pins.Repository, "https://"+host+"/") {
		return pins, errors.New("snippet repository is not served from the console origin host")
	}
	return pins, nil
}

// aptPolicyOrigins returns the repository URLs apt-cache policy lists for the
// installed (***) version.
func aptPolicyOrigins(policy string) []string {
	var origins []string
	installed := false
	for line := range strings.SplitSeq(policy, "\n") {
		fields := strings.Fields(line)
		switch {
		case strings.HasPrefix(line, " *** "):
			installed = true
		case installed && len(fields) >= 2 && strings.HasPrefix(line, "       "):
			if strings.HasPrefix(fields[1], "https://") {
				origins = append(origins, fields[1])
			}
		case installed:
			return origins
		}
	}
	return origins
}

// rpmSignatureKeyIDs extracts signer key IDs from rpm's pgpsig rendering.
var rpmSignatureKeyID = regexp.MustCompile(`Key ID ([0-9a-fA-F]{16,64})`)

func rpmSignatureKeyIDs(signatures string) []string {
	var ids []string
	for _, match := range rpmSignatureKeyID.FindAllStringSubmatch(signatures, -1) {
		ids = append(ids, strings.ToUpper(match[1]))
	}
	return ids
}
