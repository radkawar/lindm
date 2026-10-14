// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/custody"
	"lindm/internal/gendoc"
	"lindm/internal/labhost"
	"lindm/internal/labmatrix"
	"lindm/internal/packaging"
	"lindm/internal/platform"
)

const matrixUsage = "usage: lab matrix plan|report|import|run [flags]"

func runMatrix(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New(matrixUsage)
	}
	switch args[0] {
	case "plan":
		return runMatrixPlan(args[1:], stdout, stderr)
	case "report":
		return runMatrixReport(args[1:], stdout, stderr)
	case "import":
		return runMatrixImport(ctx, args[1:], stderr)
	case "run":
		return runMatrixRun(ctx, args[1:], stdout, stderr)
	default:
		return errors.New(matrixUsage)
	}
}

// matrixSelection is the shared platform/cell/architecture selection.
type matrixSelection struct {
	root, platforms, cells, architecture string
	manifestID                           string
	requalifyDue                         bool
}

func newMatrixSelection(flags *flag.FlagSet) *matrixSelection {
	s := new(matrixSelection)
	flags.StringVar(&s.root, "root", ".", "checkout holding lab/matrix.json, lab/images and lab/ledger.json")
	flags.StringVar(&s.platforms, "platform", "", "comma-separated registry keys (default: every Tier 1/2 release)")
	flags.StringVar(&s.cells, "cells", "", "comma-separated matrix cells (default: all)")
	flags.StringVar(&s.architecture, "architecture", "", "x86_64 or aarch64 (default: every registry architecture)")
	flags.StringVar(&s.manifestID, "manifest-id", "", "prefer this pinned image for an explicit single platform and architecture (owner-selected boot topology)")
	flags.BoolVar(&s.requalifyDue, "rolling-requalification", false, "select due rolling-snapshot lanes from the matrix periodic schedule")
	return s
}

func (s *matrixSelection) plan() (*labmatrix.Inputs, []*labmatrix.Cell, error) {
	in, err := labmatrix.Load(s.root)
	if err != nil {
		return nil, nil, err
	}
	releases, err := labmatrix.Platforms(splitList(s.platforms))
	if err != nil {
		return nil, nil, err
	}
	if s.manifestID != "" {
		index := slices.IndexFunc(in.Manifests, func(m *labmatrix.Manifest) bool { return m.Image.GetId() == s.manifestID })
		if index < 0 {
			return nil, nil, fmt.Errorf("unknown pinned manifest %q", s.manifestID)
		}
		selected := in.Manifests[index]
		if len(releases) != 1 || releases[0].Key != selected.Release.Key || s.architecture != selected.Architecture {
			return nil, nil, errors.New("-manifest-id requires its exact single -platform and -architecture")
		}
		in.PreferredManifest = selected.Image.GetId()
	}
	names := splitList(s.cells)
	if s.requalifyDue {
		if s.cells != "" {
			return nil, nil, errors.New("-rolling-requalification uses the matrix's complete lane set, not -cells")
		}
		names = in.Matrix.GetRollingRequalificationCells()
		if len(names) == 0 {
			return nil, nil, errors.New("matrix has no rolling requalification lanes")
		}
	}
	specs, err := in.Cells(names)
	if err != nil {
		return nil, nil, err
	}
	cells := in.Plan(releases, specs)
	if s.architecture != "" {
		cells = slices.DeleteFunc(cells, func(c *labmatrix.Cell) bool { return c.Architecture != s.architecture })
	}
	if s.requalifyDue {
		now := time.Now()
		cells = slices.DeleteFunc(cells, func(c *labmatrix.Cell) bool { return !c.RequalificationDue(now) })
	}
	return in, cells, nil
}

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func runMatrixPlan(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("matrix plan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	selection := newMatrixSelection(flags)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("matrix plan takes no positional arguments")
	}
	_, cells, err := selection.plan()
	if err != nil {
		return err
	}
	out := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(out, "PLATFORM\tARCH\tCELL\tSTATE\tMANIFEST\tDETAIL"); err != nil {
		return err
	}
	for _, c := range cells {
		manifest, detail := "-", c.Reason
		if c.Manifest != nil {
			manifest = c.Manifest.Image.GetId()
		}
		if e := c.Entry; e != nil && (c.State == labmatrix.Pass || c.State == labmatrix.Fail) {
			detail = fmt.Sprintf("%s %s sha256:%s", e.GetRecorded().AsTime().Format(time.DateOnly), e.GetEvidence(), e.GetSha256())
		}
		if _, err := fmt.Fprintf(out, "%s\t%s\t%s\t%s\t%s\t%s\n", c.Release.Key, c.Architecture, c.Spec.GetName(), c.State, manifest, detail); err != nil {
			return err
		}
	}
	return out.Flush()
}

func runMatrixReport(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("matrix report", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", ".", "repository root")
	check := flags.Bool("check", false, "fail if the generated table differs instead of rewriting it")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("matrix report takes no positional arguments")
	}
	block, err := labmatrix.DocBlock(*root)
	if err != nil {
		return err
	}
	stale, err := gendoc.Sync(*root, []gendoc.Block{block}, !*check)
	if err != nil {
		return err
	}
	if *check && len(stale) > 0 {
		return fmt.Errorf("lab matrix table is stale; run lab matrix report: %s", strings.Join(stale, ", "))
	}
	for _, file := range stale {
		if _, err := fmt.Fprintln(stdout, "regenerated", file); err != nil {
			return err
		}
	}
	return nil
}

func runMatrixImport(ctx context.Context, args []string, stderr io.Writer) error {
	flags := flag.NewFlagSet("matrix import", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", ".", "checkout holding lab/matrix.json and lab/ledger.json")
	key := flags.String("platform", "", "registry key")
	cell := flags.String("cell", "", "matrix cell")
	arch := flags.String("architecture", "", "x86_64 or aarch64")
	manifest := flags.String("manifest", "", "image manifest id the record booted; required for rolling releases")
	recovery := flags.String("recovery-manifest", "", "recovery image manifest id a device-actions record booted; required for rolling releases")
	evidence := flags.String("evidence", "", "evidence file path as recorded")
	digest := flags.String("sha256", "", "documented record SHA-256; required when the file is not readable here")
	verdict := flags.String("verdict", "pass", "pass or fail")
	recorded := flags.String("recorded", "", "record time (RFC 3339 or YYYY-MM-DD); defaults to the readable file's modification time")
	scope := flags.String("scope", "", "named subset the record covers")
	reference := flags.String("reference", "", "docs/verification.md anchor narrating the record, e.g. #resource-kind-coverage")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *key == "" || *cell == "" || *arch == "" || *evidence == "" {
		return errors.New("matrix import requires -platform, -cell, -architecture and -evidence; no positional arguments")
	}
	in, err := labmatrix.Load(*root)
	if err != nil {
		return err
	}
	release, ok := platform.Lookup(*key)
	if !ok {
		return fmt.Errorf("unknown platform %q", *key)
	}
	specs, err := in.Cells([]string{*cell})
	if err != nil {
		return err
	}
	if !slices.Contains(release.Architectures, *arch) {
		return fmt.Errorf("%s has no %s architecture", release.Key, *arch)
	}
	entry := &labv1.MatrixLedgerEntry{Platform: release.Key, Cell: *cell, Architecture: *arch, Evidence: homeRelative(*evidence), Source: labv1.MatrixSource_MATRIX_SOURCE_IMPORT, Scope: *scope, Reference: *reference}
	if err := in.BindImportManifests(entry, release, specs[0], *manifest, *recovery); err != nil {
		return err
	}
	switch *verdict {
	case "pass":
		entry.Verdict = labv1.MatrixVerdict_MATRIX_VERDICT_PASS
	case "fail":
		entry.Verdict = labv1.MatrixVerdict_MATRIX_VERDICT_FAIL
	default:
		return errors.New("-verdict must be pass or fail")
	}
	path := expandHome(*evidence)
	if info, statErr := os.Stat(path); statErr == nil {
		var sum string
		if *cell == "production-release-signing" {
			sum, err = productionSigningEvidenceSHA256(path, *scope, *manifest)
		} else {
			sum, err = matrixImportEvidenceSHA256(path, *cell, *scope)
		}
		if err != nil {
			return err
		}
		if *digest != "" && *digest != sum {
			return fmt.Errorf("evidence %s has SHA-256 %s, not the documented %s", path, sum, *digest)
		}
		entry.Sha256, entry.Verified = sum, true
		entry.Recorded = timestamppb.New(info.ModTime())
	} else if errors.Is(statErr, os.ErrNotExist) || errors.Is(statErr, os.ErrPermission) {
		if *cell == "production-release-signing" {
			return errors.New("production signing import requires readable tests-only evidence and reverified test evidence hashes")
		}
		if *digest == "" {
			return fmt.Errorf("evidence %s is not readable here; -sha256 is required", path)
		}
		if *cell == "deploy" && *scope == "" {
			return errors.New("unscoped deploy import requires readable evidence so first-run-only scope cannot be discarded")
		}
		entry.Sha256 = *digest
	} else {
		return statErr
	}
	if *recorded != "" {
		when, err := parseRecorded(*recorded)
		if err != nil {
			return err
		}
		entry.Recorded = timestamppb.New(when)
	}
	if entry.Recorded == nil {
		return errors.New("-recorded is required for an unreadable evidence file")
	}
	if entry.Revision, entry.MainlineRevision, err = sourceRevision(ctx, *root); err != nil {
		return err
	}
	return labmatrix.Append(filepath.Join(*root, labmatrix.LedgerFile), entry)
}

func parseRecorded(s string) (time.Time, error) {
	if when, err := time.Parse(time.RFC3339, s); err == nil {
		return when, nil
	}
	when, err := time.Parse(time.DateOnly, s)
	if err != nil {
		return time.Time{}, errors.New("-recorded must be RFC 3339 or YYYY-MM-DD")
	}
	return when, nil
}

// homeRelative stores evidence under the operator's home as ~/..., so the
// committed ledger does not depend on one account's home path.
func homeRelative(path string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	if abs, err := filepath.Abs(expandHome(path)); err == nil {
		path = abs
	}
	if rel, ok := strings.CutPrefix(path, home+"/"); ok {
		return "~/" + rel
	}
	return path
}

func expandHome(path string) string {
	for _, prefix := range []string{"~/", "$HOME/"} {
		if rel, ok := strings.CutPrefix(path, prefix); ok {
			if home, err := os.UserHomeDir(); err == nil {
				return filepath.Join(home, rel)
			}
		}
	}
	return path
}

// sourceRevision names the checkout commit, suffixed "-dirty" when the tree
// has uncommitted or untracked changes, and the newest main-branch commit it
// contains: landing republishes a worktree's change rather than its commits,
// so only the mainline ancestor stays resolvable for requalification floors.
func sourceRevision(ctx context.Context, root string) (revision, mainline string, err error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	head := &boundedBuffer{limit: 128}
	cmd := exec.CommandContext(ctx, "git", "-C", root, "rev-parse", "HEAD")
	cmd.Stdout = head
	if err := cmd.Run(); err != nil {
		return "", "", fmt.Errorf("read source revision: %w", err)
	}
	base := &boundedBuffer{limit: 128}
	cmd = exec.CommandContext(ctx, "git", "-C", root, "merge-base", "HEAD", "main")
	cmd.Stdout = base
	if err := cmd.Run(); err != nil {
		return "", "", fmt.Errorf("read mainline revision (git merge-base HEAD main): %w", err)
	}
	status := &boundedBuffer{limit: 1}
	cmd = exec.CommandContext(ctx, "git", "-C", root, "status", "--porcelain")
	cmd.Stdout = status
	if err := cmd.Run(); err != nil {
		return "", "", fmt.Errorf("read source status: %w", err)
	}
	revision = strings.TrimSpace(head.String())
	if status.written > 0 {
		revision += "-dirty"
	}
	return revision, strings.TrimSpace(base.String()), nil
}

// boundedBuffer keeps at most limit bytes and counts everything written.
type boundedBuffer struct {
	strings.Builder
	limit, written int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.written += len(p)
	if room := b.limit - b.Len(); room > 0 {
		b.Builder.Write(p[:min(room, len(p))])
	}
	return len(p), nil
}

// Agent package versions every lifecycle cell installs and upgrades between.
var matrixVersions = [2]string{"0.1.0", "0.1.1"}

// matrixRun holds the shared inputs one run prepares for every cell.
type matrixRun struct {
	root, repo, cache, evidence, self, lindmd, agent, redhatToken, revision string
	mainline                                                                string
	consoleBrowsers, consoleAdmin, consoleDevice                            string
	bootstrapFirmwareVars                                                   string
	signer                                                                  *packaging.SigningKey
	archArgs, secureBootArgs                                                map[string]*labv1.MatrixArgs
	airgap                                                                  map[string][]string
	deploy                                                                  *deployMatrixInputs
	deployIdentityPassphrase                                                []byte
	// lifecycle inputs per packaging architecture and format.
	builds     map[string][2]string
	apt        map[string]string
	pacman     map[string][2]string
	rejections map[string]map[string]string
	publicKey  map[string]string
	ledger     sync.Mutex
}

// laneInputs lists the shared inputs each lane takes; everything else comes
// from the matrix cell's fixed arguments. "diagnostics" gives each failed lane
// a private directory beside its record; SSH hosts return it, whereas a path
// inside the remote run directory was deleted with the run.
var laneInputs = map[string][]string{
	"deploy":                     {"repo", "lab", "deploy", "redhat-token-file", "evidence", "record"},
	"production-release-signing": {"repo", "lab", "diagnostics", "record"},
	"inspect":                    {"agent", "diagnostics", "record"},
	"lifecycle":                  {"repo", "build-repo", "packages", "redhat-token-file", "diagnostics", "record"},
	"dispatch":                   {"repo", "build-repo", "lindmd", "redhat-token-file", "diagnostics", "record"},
	"resources":                  {"repo", "build-repo", "lindmd", "redhat-token-file", "diagnostics", "record"},
	"encrypted":                  {"record"},
	"device-actions":             {"repo", "build-repo", "lab", "lindmd", "redhat-token-file", "recovery-manifest", "diagnostics", "record"},
	"updates":                    {"repo", "build-repo", "lab", "diagnostics", "record"},
	"assistance":                 {"repo", "build-repo", "lab", "lindmd", "evidence"},
	"enroll-from-console":        {"console-browser", "redhat-token-file", "diagnostics", "record"},
	"services":                   {"record"},
	"advisories":                 {"repo", "build-repo", "lab", "lindmd", "redhat-token-file", "diagnostics", "record"},
	"airgap":                     {"repo", "build-repo", "lab", "lindmd", "airgap", "diagnostics", "record"},
	// Provisioning needs no registration: the snippet alone installs from the
	// lindm repository, skipping prerequisites the installed system already has.
	"provision-cloud-init":  {"provision-browser", "record"},
	"provision-autoinstall": {"provision-browser", "diagnostics", "record"},
	"provision-kickstart":   {"provision-browser", "diagnostics", "record"},
	"provision-autoyast":    {"provision-browser", "diagnostics", "record"},
}

func runMatrixRun(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("matrix run", flag.ContinueOnError)
	flags.SetOutput(stderr)
	selection := newMatrixSelection(flags)
	run := &matrixRun{}
	evidence := flags.String("evidence", "", "required new private directory for shared inputs, lane records and logs")
	flags.StringVar(&run.repo, "repo", ".", "checkout with the running development fixture")
	flags.StringVar(&run.cache, "cache", ".cache/lab/images", "verified image cache")
	flags.StringVar(&run.redhatToken, "redhat-token-file", "", "protected Red Hat offline-token file; required for entitled releases")
	flags.StringVar(&run.consoleBrowsers, "console-browser-config-dir", "", "private directory of Chromium capture configs, each owned mode0600: PLATFORM-ARCH.json (enroll-from-console) and PLATFORM-ARCH.LANE.json per provision-* lane (public-host origin with approver; each lane needs its own fresh evidenceDirectory)")
	flags.StringVar(&run.consoleAdmin, "console-admin-address", "", "optional host-loopback console listener forwarded unchanged into each fresh guest")
	flags.StringVar(&run.consoleDevice, "console-device-address", "", "optional host-loopback device listener forwarded unchanged into each fresh guest")
	flags.StringVar(&run.bootstrapFirmwareVars, "bootstrap-firmware-vars", "", "owner-key Secure Boot cells only (recovery, TPM unattended boots): package-owned noSB bootstrap NVRAM template on the selected host")
	parallel := flags.Int("parallel", 4, "maximum concurrently scheduled cells (1-32); host slots still bound guests")
	deployInputsPath := flags.String("deploy-inputs", "", "protected mode0600 JSON references to private signed releases, independent trust, offline backup custody and matching owner CLI binaries")
	deployPassphraseFD := flags.Int("deploy-backup-identity-passphrase-fd", -1, "protected anonymous pipe carrying one offline backup identity passphrase line; never serialized")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *evidence == "" || *parallel < 1 || *parallel > 32 {
		return errors.New("matrix run requires -evidence NEW_DIRECTORY and -parallel 1-32; no positional arguments")
	}
	in, cells, err := selection.plan()
	if err != nil {
		return err
	}
	if selection.requalifyDue && len(cells) == 0 {
		_, err := fmt.Fprintln(stdout, "no rolling requalification lanes are due")
		return err
	}
	cells = slices.DeleteFunc(cells, func(c *labmatrix.Cell) bool {
		if !c.Runnable() {
			_, _ = fmt.Fprintf(stderr, "skip %s %s %s: %s %s\n", c.Release.Key, c.Architecture, c.Spec.GetName(), c.State, c.Reason)
		}
		return !c.Runnable()
	})
	if len(cells) == 0 {
		return errors.New("no runnable cells selected")
	}
	for _, path := range []*string{&selection.root, &run.repo, &run.cache, evidence} {
		if *path, err = filepath.Abs(*path); err != nil {
			return err
		}
	}
	if run.consoleBrowsers != "" {
		if run.consoleBrowsers, err = filepath.Abs(run.consoleBrowsers); err != nil {
			return err
		}
	}
	run.root, run.evidence, run.archArgs, run.secureBootArgs = selection.root, *evidence, in.Matrix.GetArchitectureArgs(), in.Matrix.GetSecureBootArgs()
	if run.self, err = os.Executable(); err != nil {
		return err
	}
	if run.revision, run.mainline, err = sourceRevision(ctx, run.root); err != nil {
		return err
	}
	for _, c := range cells {
		if c.Spec.GetLane() == "deploy" && run.deploy == nil {
			if *deployInputsPath == "" {
				return errors.New("deploy matrix lane requires explicit -deploy-inputs; it never substitutes unsigned locally built packages")
			}
			run.deploy, err = readMatrixDeployInputs(*deployInputsPath)
			if err != nil {
				return err
			}
			if *deployPassphraseFD < 0 {
				return errors.New("deploy matrix lane requires -deploy-backup-identity-passphrase-fd")
			}
			run.deployIdentityPassphrase, err = custody.ReadPassphraseFD(ctx, *deployPassphraseFD, false)
			if err != nil {
				return err
			}
			defer clear(run.deployIdentityPassphrase)
			if err := syscall.Close(*deployPassphraseFD); err != nil {
				return err
			}
		}
		if inputs := laneInputs[c.Spec.GetLane()]; (slices.Contains(inputs, "console-browser") || slices.Contains(inputs, "provision-browser")) && run.consoleBrowsers == "" {
			return fmt.Errorf("%s requires -console-browser-config-dir for actual clipboard capture and screenshots", c.Spec.GetLane())
		}
		if c.Release.Native().Lab.Entitlement && run.redhatToken == "" && slices.Contains(laneInputs[c.Spec.GetLane()], "redhat-token-file") {
			return fmt.Errorf("%s %s needs -redhat-token-file", c.Release.Key, c.Spec.GetName())
		}
		if _, ok := laneInputs[c.Spec.GetLane()]; !ok {
			return fmt.Errorf("cell %s names lane %q, which has no matrix driver", c.Spec.GetName(), c.Spec.GetLane())
		}
	}
	if err := os.Mkdir(run.evidence, 0o700); err != nil {
		return err
	}
	if err := run.prepare(ctx, cells, stderr); err != nil {
		return fmt.Errorf("prepare shared inputs: %w", err)
	}
	slots := make(chan struct{}, *parallel)
	failures := make([]error, len(cells))
	var pending sync.WaitGroup
	for i, c := range cells {
		pending.Go(func() {
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
				failures[i] = ctx.Err()
				return
			}
			defer func() { <-slots }()
			failures[i] = run.cell(ctx, c, stderr)
		})
	}
	pending.Wait()
	if _, err := fmt.Fprintf(stdout, "evidence %s\nledger %s\n", run.evidence, filepath.Join(run.root, labmatrix.LedgerFile)); err != nil {
		return err
	}
	return errors.Join(failures...)
}

// prepare builds the shared inputs once: release-stamped lindmd and agent
// binaries (native fixtures refuse unstamped servers), and for lifecycle a
// development signer, both agent versions in each needed format and
// architecture, their repositories and the authentication rejection fixtures,
// all through `lab packages`.
func (r *matrixRun) prepare(ctx context.Context, cells []*labmatrix.Cell, stderr io.Writer) error {
	formats := map[string][]string{}
	var err error
	for _, c := range cells {
		inputs := laneInputs[c.Spec.GetLane()]
		if r.lindmd == "" && (slices.Contains(inputs, "lindmd") || slices.Contains(c.Spec.GetArgs(), "-local-authority")) {
			if r.lindmd, err = r.buildStamped(ctx, stderr, "lindmd"); err != nil {
				return err
			}
		}
		if r.agent == "" && slices.Contains(inputs, "agent") {
			if r.agent, err = r.buildStamped(ctx, stderr, "lindm-agent"); err != nil {
				return err
			}
		}
		if c.Spec.GetLane() != "lifecycle" {
			continue
		}
		arch := packagingArchitecture(c.Architecture)
		format := c.Release.Native().Packages.Backend.PackageFormat()
		if format == "" {
			return fmt.Errorf("%s has no native package format", c.Release.Key)
		}
		if format == string(packaging.FormatDEB) || format == string(packaging.FormatRPM) {
			// Rejection fixtures and the APT repository need both.
			formats[arch] = appendMissing(formats[arch], string(packaging.FormatDEB), string(packaging.FormatRPM))
		} else {
			formats[arch] = appendMissing(formats[arch], format)
		}
	}
	if len(formats) == 0 {
		return r.prepareAirgap(ctx, cells, stderr)
	}
	keyDir := filepath.Join(r.evidence, "inputs", "key")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		return err
	}
	signer, err := packaging.GenerateDevelopmentSigner(ctx, keyDir)
	if err != nil {
		return err
	}
	r.signer = signer
	r.builds, r.apt, r.pacman = map[string][2]string{}, map[string]string{}, map[string][2]string{}
	r.rejections, r.publicKey = map[string]map[string]string{}, map[string]string{}
	sign := []string{"-signer-home", signer.Home, "-fingerprint", signer.Fingerprint}
	for arch, list := range formats {
		dir := filepath.Join(r.evidence, "inputs", arch)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		var builds [2]string
		var results [2]packaging.BuildResult
		for i, version := range matrixVersions {
			out := filepath.Join(dir, version)
			builds[i] = filepath.Join(out, "build.json")
			if err := r.packages(ctx, stderr, append([]string{"build", "-repo", r.root, "-version", version, "-revision", r.revision, "-output", out, "-development-key", "-formats", strings.Join(list, ","), "-arch", arch, "-record", builds[i]}, sign...)...); err != nil {
				return err
			}
			if err := readLabEvidence(builds[i], &results[i]); err != nil {
				return err
			}
		}
		r.builds[arch], r.publicKey[arch] = builds, results[0].PublicKey
		r.rejections[arch] = map[string]string{}
		if slices.Contains(list, string(packaging.FormatDEB)) {
			repo := filepath.Join(dir, "apt", "repository.json")
			args := append([]string{"apt", "-output", filepath.Dir(repo), "-development-key", "-record", repo}, sign...)
			if err := r.packages(ctx, stderr, append(args, artifactPaths(results[:], packaging.FormatDEB)...)...); err != nil {
				return err
			}
			fixtures := filepath.Join(dir, "rejections", "fixtures.json")
			if err := r.packages(ctx, stderr, append([]string{"rejection-fixtures", "-build", builds[0], "-apt-repository", repo, "-output", filepath.Dir(fixtures), "-record", fixtures}, sign...)...); err != nil {
				return err
			}
			r.apt[arch] = repo
			r.rejections[arch][string(packaging.FormatDEB)], r.rejections[arch][string(packaging.FormatRPM)] = fixtures, fixtures
		}
		if slices.Contains(list, string(packaging.FormatArch)) {
			var repos [2]string
			for i, version := range matrixVersions {
				repos[i] = filepath.Join(dir, "pacman-"+version, "repository.json")
				args := append([]string{string(packaging.FormatArch), "-output", filepath.Dir(repos[i]), "-development-key", "-record", repos[i]}, sign...)
				if err := r.packages(ctx, stderr, append(args, artifactPaths(results[i:i+1], packaging.FormatArch)...)...); err != nil {
					return err
				}
			}
			fixtures := filepath.Join(dir, "rejections-pacman", "fixtures.json")
			if err := r.packages(ctx, stderr, append([]string{"rejection-fixtures", "-arch", "-build", builds[0], "-output", filepath.Dir(fixtures), "-record", fixtures}, sign...)...); err != nil {
				return err
			}
			r.pacman[arch] = repos
			r.rejections[arch][string(packaging.FormatArch)] = fixtures
		}
	}
	return r.prepareAirgap(ctx, cells, stderr)
}

func appendMissing(list []string, values ...string) []string {
	for _, f := range values {
		if !slices.Contains(list, f) {
			list = append(list, f)
		}
	}
	return list
}

func artifactPaths(results []packaging.BuildResult, format packaging.Format) []string {
	var out []string
	for _, result := range results {
		for _, a := range result.Artifacts {
			if a.Format == format {
				out = append(out, a.Path)
			}
		}
	}
	return out
}

// packages runs one `lab packages` command in process, keeping its record
// output out of the matrix's own stdout.
func (r *matrixRun) packages(ctx context.Context, stderr io.Writer, args ...string) error {
	_, _ = fmt.Fprintln(stderr, "lab packages", args[0])
	if err := runPackages(ctx, args, io.Discard, stderr); err != nil {
		return fmt.Errorf("lab packages %s: %w", args[0], err)
	}
	return nil
}

func packagingArchitecture(arch string) string {
	if arch == "aarch64" {
		return "arm64"
	}
	return "amd64"
}

// buildStamped compiles a static release-stamped executable for this host from
// the run's source checkout, as remote staging does.
func (r *matrixRun) buildStamped(ctx context.Context, stderr io.Writer, name string) (string, error) {
	out := filepath.Join(r.evidence, "bin", name)
	_, _ = fmt.Fprintln(stderr, "go build", name)
	cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-ldflags", "-X lindm/internal/agent/buildinfo.Version="+matrixVersions[0], "-o", out, "./cmd/"+name)
	cmd.Dir = r.root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	cmd.Stdout, cmd.Stderr = stderr, stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("build %s: %w", name, err)
	}
	return out, nil
}

// cell schedules one lane through `lab vm` admission in a child process and
// records its verdict. An interrupted run records nothing.
func (r *matrixRun) cell(ctx context.Context, c *labmatrix.Cell, stderr io.Writer) error {
	name := fmt.Sprintf("%s %s %s", c.Release.Key, c.Architecture, c.Spec.GetName())
	dir := filepath.Join(r.evidence, c.Release.Key)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	base := filepath.Join(dir, c.Spec.GetName()+"-"+c.Architecture)
	record := base + ".json"
	args, err := r.laneArgs(c, base)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	pinned := base + ".manifest.json"
	if err := retainMatrixManifest(filepath.Join(r.root, c.Manifest.Path), pinned, c.Manifest.SHA256); err != nil {
		return fmt.Errorf("%s: retain snapshot manifest: %w", name, err)
	}
	args = labhost.SetFlag(args, "manifest", pinned)
	if diagnostics := labhost.FlagValue(args, "diagnostics"); diagnostics != "" {
		if err := os.Mkdir(diagnostics, 0o700); err != nil {
			return err
		}
	}
	if c.Recovery != nil {
		recoveryPin := base + ".recovery-manifest.json"
		if err := retainMatrixManifest(filepath.Join(r.root, c.Recovery.Path), recoveryPin, c.Recovery.SHA256); err != nil {
			return fmt.Errorf("%s: retain recovery manifest: %w", name, err)
		}
		args = labhost.SetFlag(args, "recovery-manifest", recoveryPin)
	}
	if slices.Contains(laneInputs[c.Spec.GetLane()], "evidence") {
		record = filepath.Join(base, c.Spec.GetLane()+".json")
	}
	var identityPipe *os.File
	if c.Spec.GetLane() == "deploy" {
		identityPipe, err = protectedDeployPipe(r.deployIdentityPassphrase)
		if err != nil {
			return err
		}
		defer func() { _ = identityPipe.Close() }()
		args = append(args, "-backup-identity-passphrase-fd", "0")
	}
	log, err := os.OpenFile(base+".log", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stderr, "start %s: lab %s\n", name, strings.Join(args, " "))
	cmd := exec.CommandContext(ctx, r.self, args...)
	cmd.Stdout, cmd.Stderr = log, log
	if identityPipe != nil {
		cmd.Stdin = identityPipe
	}
	// Let the lane revoke authority and destroy its guests before exiting.
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 5 * time.Minute
	laneErr := cmd.Run()
	if err := log.Close(); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return fmt.Errorf("%s: interrupted: %w", name, ctx.Err())
	}
	verdict, evidence := labv1.MatrixVerdict_MATRIX_VERDICT_PASS, record
	if _, statErr := os.Stat(record); laneErr != nil || statErr != nil {
		verdict = labv1.MatrixVerdict_MATRIX_VERDICT_FAIL
		if statErr != nil {
			evidence = base + ".log"
		}
	}
	sum, err := labmatrix.FileSHA256(evidence)
	if err != nil {
		return err
	}
	entry := &labv1.MatrixLedgerEntry{Platform: c.Release.Key, Cell: c.Spec.GetName(), Architecture: c.Architecture, Manifest: c.Manifest.Image.GetId(), ManifestSha256: c.Manifest.SHA256, RepositorySnapshotDate: c.Manifest.Image.GetRepositorySnapshotDate(), Verdict: verdict, Evidence: homeRelative(evidence), Sha256: sum, Recorded: timestamppb.Now(), Revision: r.revision, MainlineRevision: r.mainline, Source: labv1.MatrixSource_MATRIX_SOURCE_RUN, Verified: true}
	entry.RepositoryClosureSha256 = c.Manifest.Image.GetRepositorySnapshotManifestSha256()
	entry.RepositoryMetadataSha256 = c.Manifest.Image.GetRepositorySnapshotRepomdSha256()
	if c.Recovery != nil {
		entry.RecoveryManifest = c.Recovery.Image.GetId()
		entry.RecoveryManifestSha256 = c.Recovery.SHA256
		entry.RecoveryRepositorySnapshotDate = c.Recovery.Image.GetRepositorySnapshotDate()
		entry.RecoveryRepositoryClosureSha256 = c.Recovery.Image.GetRepositorySnapshotManifestSha256()
		entry.RecoveryRepositoryMetadataSha256 = c.Recovery.Image.GetRepositorySnapshotRepomdSha256()
	}
	if c.Spec.GetLane() == "production-release-signing" {
		entry.Scope = productionSigningScope
		if verdict == labv1.MatrixVerdict_MATRIX_VERDICT_PASS {
			if _, err := productionSigningEvidenceSHA256(record, entry.Scope, c.Manifest.Image.GetId()); err != nil {
				return fmt.Errorf("%s: invalid tests-only evidence: %w", name, err)
			}
		}
	}
	if c.Spec.GetLane() == "advisories" && verdict == labv1.MatrixVerdict_MATRIX_VERDICT_PASS {
		entry.Scope, err = advisoryRecordScope(record)
		if err != nil {
			return fmt.Errorf("%s: record qualification scope: %w", name, err)
		}
	}
	r.ledger.Lock()
	err = labmatrix.Append(filepath.Join(r.root, labmatrix.LedgerFile), entry)
	r.ledger.Unlock()
	_, _ = fmt.Fprintf(stderr, "%s %s: %s sha256:%s\n", verdict, name, evidence, sum)
	if err != nil {
		return err
	}
	if verdict != labv1.MatrixVerdict_MATRIX_VERDICT_PASS {
		return fmt.Errorf("%s failed: %w (log %s.log)", name, laneErr, base)
	}
	return nil
}

func advisoryRecordScope(path string) (scope string, err error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	var record struct {
		Advisories struct {
			Scope string `json:"scope"`
		} `json:"advisories"`
	}
	if err := json.NewDecoder(io.LimitReader(file, 32<<20)).Decode(&record); err != nil {
		return "", err
	}
	switch record.Advisories.Scope {
	case "partial-feed matching", "native feed matching; not complete device coverage":
		return record.Advisories.Scope, nil
	default:
		return "", errors.New("advisory lane omitted its explicit coverage scope")
	}
}

// retainMatrixManifest preserves the exact planned pin and runs the lane against
// those bytes, not a checkout file that another process may change while queued.
func retainMatrixManifest(source, destination, expected string) (err error) {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, input.Close()) }()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, output.Close()) }()
	digest := sha256.New()
	const maxManifestBytes = 16 << 20
	n, err := io.Copy(io.MultiWriter(output, digest), io.LimitReader(input, maxManifestBytes+1))
	if err != nil {
		return err
	}
	if n > maxManifestBytes || fmt.Sprintf("%x", digest.Sum(nil)) != expected {
		return errors.New("image manifest changed after planning")
	}
	return nil
}

// laneArgs derives the lane command line: the cell's fixed arguments, the
// image manifests, and the shared inputs the lane takes for this release.
func (r *matrixRun) laneArgs(c *labmatrix.Cell, base string) ([]string, error) {
	lane := c.Spec.GetLane()
	args := append([]string{"vm", lane}, c.Spec.GetArgs()...)
	if lane == "production-release-signing" {
		args = append(args, "-work-dir", r.evidence)
	}
	// A release (or guest architecture) without the owned-boot UKI fixture
	// qualifies recovery only through measured GRUB; vmlab refuses the owned
	// fixture for it.
	if lane == "device-actions" && strings.HasPrefix(labhost.FlagValue(args, "wipe-phase"), "recovery-") && c.Release.Lab.OwnedBootUnavailableFor(c.Architecture) != "" {
		args = labhost.SetFlag(args, "recovery-boot-mode", "measured-grub")
	}
	// Desktop lanes default to GNOME; media that install only their own
	// desktop (Mint's Cinnamon, Pop!_OS's COSMIC, Omarchy's Hyprland) refuse
	// it, so those releases boot their sole maintained lab desktop.
	if lane == "device-actions" || lane == "assistance" {
		if desktop := matrixLabDesktop(c.Release); desktop != "" && labhost.FlagValue(args, "desktop") == "" {
			args = labhost.SetFlag(args, "desktop", desktop)
		}
	}
	args = append(args, "-manifest", filepath.Join(r.root, c.Manifest.Path), "-cache", r.cache)
	if vmHasHardwareFlags(lane) {
		args = append(args, r.archArgs[c.Architecture].GetArgs()...)
	}
	if c.Spec.GetSecureBoot() {
		secureBoot, ok := r.secureBootArgs[c.Architecture]
		if !vmHasHardwareFlags(lane) || !ok {
			return nil, fmt.Errorf("%s requires Secure Boot firmware arguments for %s", c.Spec.GetName(), c.Architecture)
		}
		args = append(args, secureBoot.GetArgs()...)
	}
	if slices.Contains(c.Spec.GetCapabilities(), string(platform.RecoverySanitize)) {
		// A declared stock GRUB chain selects measured GRUB unless that
		// architecture's signed GRUB records no measurements, or the guest
		// kernel cannot bind the TPM the lab attaches there (Lab.TPM.Unobservable:
		// measured recovery is proven by a fresh TPM quote); then the
		// owned-boot UKI fixture is the only recovery path.
		if c.Release.Quirks.RecoveryGRUB.Entries != "" && c.Release.Lab.MeasuredGRUBUnavailableFor(c.Architecture) == "" && !slices.Contains(c.Release.Lab.TPM.Unobservable, c.Architecture) {
			args = labhost.SetFlag(args, "recovery-boot-mode", "measured-grub")
		}
	}
	// Owner-key releases (no vendor Secure Boot trust) install under a noSB
	// bootstrap template, then enroll a run-only owner signer: recovery and
	// the TPM unattended-boot phase alike.
	if c.Spec.GetSecureBoot() && c.Release.Quirks.RecoveryOwnerKey {
		if r.bootstrapFirmwareVars == "" {
			return nil, errors.New("owner-key Secure Boot matrix cells require -bootstrap-firmware-vars")
		}
		args = labhost.SetFlag(args, "bootstrap-firmware-vars", r.bootstrapFirmwareVars)
	}
	if c.Spec.GetCapabilityKinds() {
		kinds := splitList(labhost.FlagValue(args, "kinds"))
		for _, k := range c.Kinds {
			kinds = appendMissing(kinds, string(k))
		}
		args = labhost.SetFlag(args, "kinds", strings.Join(kinds, ","))
	}
	native := c.Release.Native()
	arch := packagingArchitecture(c.Architecture)
	for _, input := range laneInputs[lane] {
		switch input {
		case "agent":
			args = append(args, "-agent", r.agent)
		case "repo":
			args = append(args, "-repo", r.repo)
		case "build-repo":
			args = append(args, "-build-repo", r.root)
		case "lab":
			args = append(args, "-lab", r.self)
		case "lindmd":
			args = append(args, "-lindmd", r.lindmd)
		case "deploy":
			if r.deploy == nil {
				return nil, errors.New("missing explicit signed deployment inputs")
			}
			args = append(args, r.deploy.args()...)
			args = append(args, "-work-dir", r.evidence)
		case "airgap":
			args = append(args, r.airgap[c.Release.Key+"/"+c.Architecture]...)
			// "diagnostics" is its own input: a second -diagnostics flag here
			// made the matrix create one directory and the lane write another.
			args = append(args, "-work-dir", r.evidence)
		case "console-browser", "provision-browser":
			config := c.Release.Key + "-" + c.Architecture + ".json"
			if input == "provision-browser" {
				// One file per provision lane: a release offering two formats
				// runs both lanes, and each capture refuses an existing
				// evidence directory.
				config = c.Release.Key + "-" + c.Architecture + "." + c.Spec.GetLane() + ".json"
			}
			args = append(args, "-repo", r.root, "-lab-binary", r.self, "-browser-config", filepath.Join(r.consoleBrowsers, config))
			if r.consoleAdmin != "" {
				args = append(args, "-admin-address", r.consoleAdmin)
			}
			if r.consoleDevice != "" {
				args = append(args, "-device-address", r.consoleDevice)
			}
		case "record":
			args = append(args, "-record", base+".json")
		case "diagnostics":
			args = append(args, "-diagnostics", base+".diagnostics")
		case "evidence":
			args = append(args, "-evidence", base)
		case "redhat-token-file":
			if native.Lab.Entitlement {
				args = append(args, "-redhat-token-file", r.redhatToken)
				// Registration reaches the vendor, so a registered lane needs
				// explicit guest egress; device-actions grants its own.
				if lane != "device-actions" && !slices.Contains(args, "-allow-network") {
					args = append(args, "-allow-network")
				}
			}
		case "recovery-manifest":
			if c.Recovery == nil {
				return nil, errors.New("no same-release ordinary recovery manifest matches the selected topology")
			}
			args = append(args, "-recovery-manifest", filepath.Join(r.root, c.Recovery.Path))
		case "packages":
			format := native.Packages.Backend.PackageFormat()
			builds := r.builds[arch]
			args = append(args, "-first-build", builds[0], "-second-build", builds[1], "-rejections", r.rejections[arch][format], "-public-key", r.publicKey[arch], "-fingerprint", r.signer.Fingerprint)
			switch packaging.Format(format) {
			case packaging.FormatDEB:
				args = append(args, "-apt-repository", r.apt[arch])
			case packaging.FormatArch:
				args = append(args, "-arch-first-repository", r.pacman[arch][0], "-arch-second-repository", r.pacman[arch][1])
			}
			if slices.Contains(c.Spec.GetArgs(), "-local-authority") {
				args = append(args, "-lindmd", r.lindmd)
			}
		}
	}
	return args, nil
}

// matrixLabDesktop is the release's only maintained lab desktop when GNOME,
// the desktop lanes' default, is not among them; "" keeps that default.
func matrixLabDesktop(r *platform.Release) string {
	desktops := r.Lab.Session.Desktops
	if _, gnome := desktops["gnome"]; gnome || len(desktops) != 1 {
		return ""
	}
	for desktop := range desktops {
		return desktop
	}
	return ""
}
