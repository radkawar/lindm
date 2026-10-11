package labhost

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/platform"
)

// BaselineOptions explicitly authorizes the maintained package transaction. The
// caller must reserve an evidence file before invoking this mutating operation.
type BaselineOptions struct {
	Host        *labv1.LabHost
	RepoDir     string
	Diagnostics io.Writer
}

// BaselinePackage is an observation from dpkg, not another configuration schema.
type BaselinePackage struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

type BaselineSnapshot struct {
	Distribution  string                     `json:"distribution"`
	Release       string                     `json:"release"`
	Description   string                     `json:"description"`
	Architecture  string                     `json:"architecture"`
	User          string                     `json:"user"`
	UID           uint32                     `json:"uid"`
	Home          string                     `json:"home"`
	CPUs          uint32                     `json:"cpus"`
	MemoryMib     uint32                     `json:"memory_mib"`
	Groups        []string                   `json:"groups"`
	SessionGroups []string                   `json:"session_groups"`
	KVMOpen       bool                       `json:"kvm_open"`
	KVMError      string                     `json:"kvm_error,omitempty"`
	Packages      map[string]BaselinePackage `json:"packages"`
	UbuntuSources string                     `json:"ubuntu_sources"`
}

type BaselinePackageChange struct {
	Package string          `json:"package"`
	Before  BaselinePackage `json:"before"`
	After   BaselinePackage `json:"after"`
}

type BaselineFirmware struct {
	Package      string `json:"package"`
	Version      string `json:"version"`
	Path         string `json:"path"`
	ResolvedPath string `json:"resolved_path"`
	SHA256       string `json:"sha256"`
}

type BaselineTool struct {
	Path          string            `json:"path"`
	ResolvedPath  string            `json:"resolved_path"`
	Packages      map[string]string `json:"packages"`
	VersionOutput string            `json:"version_output"`
}

// BaselineResult is returned even after a failed transaction. APT changes cannot
// safely be rolled back on a shared host; before/after evidence makes partial
// completion explicit. Host is populated only after readiness has succeeded.
type BaselineResult struct {
	StartedAt                 time.Time               `json:"started_at"`
	FinishedAt                time.Time               `json:"finished_at"`
	Ready                     bool                    `json:"ready"`
	Error                     string                  `json:"error,omitempty"`
	HostName                  string                  `json:"host_name"`
	PinFile                   string                  `json:"pin_file,omitempty"`
	PinSHA256                 string                  `json:"pin_sha256,omitempty"`
	Before                    *BaselineSnapshot       `json:"before,omitempty"`
	After                     *BaselineSnapshot       `json:"after,omitempty"`
	PackageChanges            []BaselinePackageChange `json:"package_changes"`
	GroupsAdded               []string                `json:"groups_added"`
	PackagesRequested         []string                `json:"packages_requested"`
	DerivedPins               []string                `json:"derived_pins,omitempty"`
	CandidatesBefore          string                  `json:"candidates_before,omitempty"`
	CandidatesAfterRefresh    string                  `json:"candidates_after_refresh,omitempty"`
	APTTransaction            string                  `json:"apt_transaction,omitempty"`
	APTSourcePath             string                  `json:"apt_source_path,omitempty"`
	APTSourceSHA256           string                  `json:"apt_source_sha256,omitempty"`
	MembershipChangeAttempted bool                    `json:"membership_change_attempted"`
	WorkDirectory             string                  `json:"work_directory,omitempty"`
	WorkDirectoryCreated      bool                    `json:"work_directory_created"`
	SuperminKernel            *BaselineSuperminKernel `json:"supermin_kernel,omitempty"`
	Firmware                  []BaselineFirmware      `json:"firmware,omitempty"`
	Tools                     map[string]BaselineTool `json:"tools,omitempty"`
	Host                      *labv1.LabHost          `json:"-"`
}

// RunBaseline installs exact reviewed Ubuntu package versions, adds only the
// authorized r account to kvm when necessary, stages a private readable copy of
// the running kernel's packaged image for libguestfs, and probes a fresh user
// session. It never upgrades the distribution, removes packages, enables
// services, edits repositories, changes /boot or device modes, or starts a
// container/guest/listener.
func RunBaseline(ctx context.Context, opts BaselineOptions) (result *BaselineResult, resultErr error) {
	result = &BaselineResult{StartedAt: time.Now().UTC()}
	defer func() {
		result.FinishedAt = time.Now().UTC()
		if resultErr != nil {
			result.Error = resultErr.Error()
		}
	}()
	if opts.Host == nil {
		return result, errors.New("labhost: baseline requires an explicit host")
	}
	result.HostName = opts.Host.GetName()
	if opts.Host.GetTransport() != "local" && opts.Host.GetTransport() != "ssh" {
		return result, errors.New("labhost: baseline supports only local or ssh transport")
	}
	before, err := baselineSnapshot(ctx, opts, "")
	if err != nil {
		return result, fmt.Errorf("discover baseline host: %w", err)
	}
	result.Before = before
	// Maintained pins are per registry release (lab/baseline/<key>.packages)
	// and installed with APT.
	release := platform.Identify(platform.OSRelease{ID: before.Distribution, VersionID: before.Release})
	if release.Native().Packages.Backend != platform.BackendAPT || !slices.Contains([]string{"amd64", "arm64"}, before.Architecture) {
		return result, fmt.Errorf("labhost: unsupported baseline host %s %s %s; maintained pins are APT package pins for amd64/arm64", before.Distribution, before.Release, before.Architecture)
	}
	if before.UID == 0 {
		return result, errors.New("labhost: run baseline as the intended unprivileged lab user, not root; privilege is obtained only with sudo -n")
	}
	result.PinFile = "lab/baseline/" + release.Key + ".packages"
	pins, pinData, err := loadBaselinePins(opts.RepoDir, result.PinFile)
	if err != nil {
		return result, err
	}
	digest := sha256.Sum256(pinData)
	result.PinSHA256 = hex.EncodeToString(digest[:])
	derived, err := baselineDerivedPins(before.Packages, pins)
	if err != nil {
		return result, err
	}
	pins = append(pins, derived...)
	result.DerivedPins = derived
	result.PackagesRequested = pins
	host, err := baselineHost(opts.Host, before)
	if err != nil {
		return result, err
	}
	if err := Validate(&labv1.LabConfig{Hosts: []*labv1.LabHost{host}}); err != nil {
		return result, fmt.Errorf("validate proposed native host before mutation: %w", err)
	}
	if err := validateBaselineSources(before.UbuntuSources, before.Architecture); err != nil {
		return result, fmt.Errorf("baseline requires official Ubuntu sources in %s; existing repositories and keys were not changed: %w", baselineAPTSourcePath, err)
	}
	result.APTSourcePath = baselineAPTSourcePath
	sourceDigest := sha256.Sum256([]byte(before.UbuntuSources))
	result.APTSourceSHA256 = hex.EncodeToString(sourceDigest[:])
	// Snapshot even after a partial apt/usermod failure, including cancellation.
	// The recovery observation is separately bounded and performs no mutation.
	defer func() {
		if result.After == nil {
			observeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 45*time.Second)
			defer cancel()
			result.After, err = baselineSnapshot(observeCtx, opts, before.User)
			if err != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("observe final baseline state: %w", err))
			}
		}
		if result.After != nil {
			result.PackageChanges = baselineChanges(before.Packages, result.After.Packages)
			for _, group := range result.After.Groups {
				if !slices.Contains(before.Groups, group) {
					result.GroupsAdded = append(result.GroupsAdded, group)
				}
			}
		}
	}()
	// Do not chmod an existing directory: it could contain another lane's work.
	// The private work directory precedes the package transaction: it holds the
	// appliance kernel, which is independent of the reviewed package pins.
	result.WorkDirectory = host.GetWorkDirectory()
	workData, workErr := baselineCommand(ctx, opts.Host, baselineAsUser(before.User, baselineWorkScript(host.GetWorkDirectory())), time.Minute, opts.Diagnostics)
	result.WorkDirectoryCreated = strings.TrimSpace(string(workData)) == "true"
	if err := workErr; err != nil {
		return result, fmt.Errorf("prepare private native work directory: %w", err)
	}
	staged, err := baselineCommand(ctx, opts.Host, baselineAsUser(before.User, baselineSuperminScript(host.GetWorkDirectory(), "/lib/modules")), 10*time.Minute, opts.Diagnostics)
	if err != nil {
		return result, fmt.Errorf("stage private readable appliance kernel from the running kernel's official package (/boot is unchanged): %w", err)
	}
	result.SuperminKernel, err = parseBaselineSupermin(staged)
	if err != nil {
		return result, err
	}
	policy, err := baselineCommand(ctx, opts.Host, baselinePolicy(pins), time.Minute, opts.Diagnostics)
	result.CandidatesBefore = string(policy)
	if err != nil {
		return result, fmt.Errorf("discover apt candidates: %w", err)
	}
	if !baselinePackagesReady(before.Packages, pins) {
		// An index refresh is not an upgrade. APT still receives only exact
		// package=version operands and refuses removals/downgrades/held changes.
		if _, err := baselineCommand(ctx, opts.Host, "sudo -n env DEBIAN_FRONTEND=noninteractive apt-get"+baselineAPTOptions+" -o APT::Update::Error-Mode=any update >&2\n", 10*time.Minute, opts.Diagnostics); err != nil {
			return result, fmt.Errorf("refresh scoped official Ubuntu indexes (other repositories and keys are untouched): %w", err)
		}
		policy, err = baselineCommand(ctx, opts.Host, baselinePolicy(pins), time.Minute, opts.Diagnostics)
		result.CandidatesAfterRefresh = string(policy)
		if err != nil {
			return result, err
		}
		transaction, err := baselineCommand(ctx, opts.Host, baselineInstall(pins), 30*time.Minute, opts.Diagnostics)
		result.APTTransaction = string(transaction)
		if err != nil {
			return result, fmt.Errorf("install maintained exact pins; if a pin was retired, review %s against apt-cache policy (do not install an unpinned substitute): %w", result.PinFile, err)
		}
	}
	if !slices.Contains(before.Groups, "kvm") {
		if before.User != "r" {
			return result, fmt.Errorf("labhost: only adding r to kvm is authorized; run user %q needs separate owner authorization", before.User)
		}
		result.MembershipChangeAttempted = true
		if _, err := baselineCommand(ctx, opts.Host, "getent group kvm >/dev/null\nsudo -n usermod -a -G kvm -- "+baselineQuote(before.User)+"\n", time.Minute, opts.Diagnostics); err != nil {
			return result, fmt.Errorf("add run user to existing kvm group: %w", err)
		}
	}
	result.After, err = baselineSnapshot(ctx, opts, before.User)
	if err != nil {
		return result, err
	}
	if !baselinePackagesReady(result.After.Packages, pins) {
		return result, errors.New("labhost: installed package state does not match every exact baseline pin")
	}
	if result.After.User != before.User || result.After.UID != before.UID || !result.After.KVMOpen || !slices.Contains(result.After.SessionGroups, "kvm") {
		return result, fmt.Errorf("labhost: fresh session for %s cannot use /dev/kvm with kvm membership: %s; inspect the host device and group policy, do not chmod /dev/kvm", before.User, result.After.KVMError)
	}
	readyData, err := baselineCommand(ctx, opts.Host, baselineAsUser(before.User, "export GOTOOLCHAIN=local\n"+baselineReadiness), 3*time.Minute, opts.Diagnostics)
	if err != nil {
		return result, fmt.Errorf("validate native tools and package-owned firmware: %w", err)
	}
	var ready struct {
		Firmware []BaselineFirmware      `json:"firmware"`
		Tools    map[string]BaselineTool `json:"tools"`
	}
	if err := json.Unmarshal(readyData, &ready); err != nil {
		return result, fmt.Errorf("decode native readiness: %w", err)
	}
	result.Firmware, result.Tools = ready.Firmware, ready.Tools
	if err := Validate(&labv1.LabConfig{Hosts: []*labv1.LabHost{host}}); err != nil {
		return result, fmt.Errorf("validate ready host entry: %w", err)
	}
	result.Host, result.Ready = host, true
	return result, nil
}

func baselineSnapshot(ctx context.Context, opts BaselineOptions, freshUser string) (*BaselineSnapshot, error) {
	script := baselineProbe
	if freshUser != "" {
		script = baselineAsUser(freshUser, script)
	}
	data, err := baselineCommand(ctx, opts.Host, script, 45*time.Second, opts.Diagnostics)
	if err != nil {
		return nil, err
	}
	var snapshot BaselineSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return nil, fmt.Errorf("decode host observation: %w", err)
	}
	return &snapshot, nil
}

func baselineAsUser(user, script string) string {
	return "sudo -n -H -u " + baselineQuote(user) + " -- /bin/bash --noprofile --norc -s <<'LINDM_BASELINE_SESSION'\nset -euo pipefail\nexport LC_ALL=C\nexport PATH=/usr/sbin:/usr/bin:/sbin:/bin\n" + script + "\nLINDM_BASELINE_SESSION\n"
}

func loadBaselinePins(repo, pinFile string) ([]string, []byte, error) {
	file, err := os.Open(filepath.Join(repo, filepath.FromSlash(pinFile)))
	if err != nil {
		return nil, nil, fmt.Errorf("open maintained baseline pins %s (use -repo CHECKOUT; add reviewed pins before installing another release): %w", pinFile, err)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err := errors.Join(readErr, file.Close()); err != nil {
		return nil, nil, err
	}
	if len(data) > 64<<10 {
		return nil, nil, errors.New("labhost: baseline pin data exceeds 64 KiB")
	}
	pins, err := parseBaselinePins(string(data))
	return pins, data, err
}

func parseBaselinePins(data string) ([]string, error) {
	var pins []string
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, version, ok := strings.Cut(line, "=")
		if !ok || name == "" || version == "" || name[0] == '-' || seen[name] {
			return nil, fmt.Errorf("labhost: invalid or duplicate exact package pin %q", line)
		}
		for _, c := range name {
			if !packageNameRune(c) {
				return nil, fmt.Errorf("labhost: invalid package name %q", name)
			}
		}
		for _, c := range version {
			if !packageVersionRune(c) {
				return nil, fmt.Errorf("labhost: invalid exact version %q", version)
			}
		}
		seen[name] = true
		pins = append(pins, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(pins) == 0 {
		return nil, errors.New("labhost: baseline has no exact package pins")
	}
	return pins, nil
}

// baselineDerivedPins pins host packages that must equal another installed
// package's exact version rather than a static reviewed version. Host-side
// recovery UKI builds need ukify, which shares systemd's source version: any
// other systemd-ukify version would pull a systemd upgrade onto a shared host
// running other lanes' guests. A version absent from the configured archive is
// refused by the install transaction rather than substituted.
func baselineDerivedPins(packages map[string]BaselinePackage, static []string) ([]string, error) {
	systemd := packages["systemd"]
	if systemd.Status != "installed" || systemd.Version == "" {
		return nil, errors.New("labhost: systemd-ukify pin requires an installed host systemd package")
	}
	for _, c := range systemd.Version {
		if !packageVersionRune(c) {
			return nil, fmt.Errorf("labhost: invalid installed systemd version %q", systemd.Version)
		}
	}
	for _, pin := range static {
		if name, _, _ := strings.Cut(pin, "="); name == "systemd-ukify" {
			return nil, errors.New("labhost: systemd-ukify is derived from the installed systemd version; remove its static pin")
		}
	}
	return []string{"systemd-ukify=" + systemd.Version}, nil
}

func baselinePackagesReady(packages map[string]BaselinePackage, pins []string) bool {
	for _, pin := range pins {
		name, version, _ := strings.Cut(pin, "=")
		installed := packages[name]
		if installed.Status != "installed" || installed.Version != version {
			return false
		}
	}
	return true
}

func baselinePolicy(pins []string) string {
	var script strings.Builder
	script.WriteString("apt-cache" + baselineAPTOptions + " policy")
	for _, pin := range pins {
		name, _, _ := strings.Cut(pin, "=")
		script.WriteByte(' ')
		script.WriteString(baselineQuote(name))
	}
	script.WriteByte('\n')
	return script.String()
}

func baselineInstall(pins []string) string {
	var script strings.Builder
	// Check all requested versions before invoking APT. Never accept a downgrade
	// simply to match a stale lock; the maintained pins must be reviewed instead.
	for _, pin := range pins {
		name, version, _ := strings.Cut(pin, "=")
		script.WriteString("installed=$(dpkg-query -W -f='${Version}' -- " + baselineQuote(name) + " 2>/dev/null || true)\n")
		script.WriteString("if [[ -n $installed ]] && dpkg --compare-versions \"$installed\" gt " + baselineQuote(version) + "; then echo " + baselineQuote("refusing downgrade of "+name+"; review the maintained baseline pin") + " >&2; exit 1; fi\n")
		// apt-cache show exits zero for an unknown version, so require the
		// exact Version stanza from the configured archive before any change.
		script.WriteString("if ! apt-cache" + baselineAPTOptions + " show -- " + baselineQuote(pin) + " | grep -xF -- " + baselineQuote("Version: "+version) + " >/dev/null; then echo " + baselineQuote("refusing "+pin+": exact version is not available from the configured official archive; review the pin, never install a substitute") + " >&2; exit 1; fi\n")
	}
	script.WriteString("sudo -n env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get" + baselineAPTOptions + " -y --no-install-recommends --no-remove -o Dpkg::Options::=--force-confold install --")
	for _, pin := range pins {
		script.WriteByte(' ')
		script.WriteString(baselineQuote(pin))
	}
	script.WriteByte('\n')
	return script.String()
}

func baselineChanges(before, after map[string]BaselinePackage) []BaselinePackageChange {
	names := make([]string, 0, len(before)+len(after))
	for name := range before {
		names = append(names, name)
	}
	for name := range after {
		if _, ok := before[name]; !ok {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	changes := make([]BaselinePackageChange, 0)
	for _, name := range names {
		if before[name] != after[name] {
			changes = append(changes, BaselinePackageChange{Package: name, Before: before[name], After: after[name]})
		}
	}
	return changes
}

func baselineHost(requested *labv1.LabHost, observed *BaselineSnapshot) (*labv1.LabHost, error) {
	if observed.CPUs == 0 || observed.MemoryMib < 1024 {
		return nil, errors.New("labhost: baseline requires at least one CPU and 1024 MiB physical memory")
	}
	host := proto.CloneOf(requested)
	cpuBudget := max(uint32(1), observed.CPUs-1)
	memoryBudget := uint32(uint64(observed.MemoryMib) * 3 / 4)
	if host.MaxVcpus == 0 {
		host.MaxVcpus = 4
	}
	if host.MaxMemoryMib == 0 {
		host.MaxMemoryMib = 8192
	}
	host.MaxVcpus = min(host.MaxVcpus, cpuBudget)
	host.MaxMemoryMib = min(host.MaxMemoryMib, memoryBudget)
	slots := max(uint32(1), min(cpuBudget/host.MaxVcpus, memoryBudget/host.MaxMemoryMib))
	if host.MaxGuests == 0 {
		host.MaxGuests = slots
	} else {
		host.MaxGuests = min(host.MaxGuests, slots)
	}
	host.Architectures = []string{observed.Architecture}
	host.Kvm, host.Runtime, host.RunnerImage = true, "native", ""
	if host.WorkDirectory == "" {
		host.WorkDirectory = "~/lindm-lab"
	}
	if strings.HasPrefix(host.WorkDirectory, "~/") {
		host.WorkDirectory = filepath.Join(observed.Home, strings.TrimPrefix(host.WorkDirectory, "~/"))
	}
	if !filepath.IsAbs(host.WorkDirectory) || strings.ContainsAny(host.WorkDirectory, "\x00\r\n") {
		return nil, errors.New("labhost: baseline work directory must be an absolute path or start with ~/")
	}
	return host, nil
}

func packageNameRune(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'
}

func packageVersionRune(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune(".+:~-", c)
}
