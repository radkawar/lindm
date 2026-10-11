// Package labmatrix plans the platform × cell lab matrix and keeps its ledger.
// It joins the declarative cell table (lab/matrix.json), the platform registry
// and the pinned image manifests into cells, derives each cell's state from the
// registry gates and the append-only ledger, and renders the verification
// documentation block. It never boots guests or builds packages: cmd/lab runs
// the lanes it plans through the lab host admission path.
package labmatrix

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/platform"
)

// Repository-relative inputs and outputs.
const (
	MatrixFile = "lab/matrix.json"
	ImagesDir  = "lab/images"
	LedgerFile = "lab/ledger.json"
)

const maxFileBytes = 16 << 20

// State is a cell's current matrix state.
type State string

const (
	Pass    State = "pass"
	Fail    State = "fail"
	NotRun  State = "not run"
	Gated   State = "gated"
	NoLane  State = "no lane"
	NoImage State = "no image"
)

// Manifest is a pinned image manifest with its repository path.
type Manifest struct {
	Path  string
	Image *labv1.ImageManifest
	// SHA256 binds the exact selected manifest bytes, including repository pins.
	SHA256 string
	// Release is the registry row the manifest identifies.
	Release *platform.Release
	// Architecture is the registry spelling (x86_64 or aarch64).
	Architecture string
}

// Encrypted reports whether the manifest is a lab encrypted-installer recipe.
func (m *Manifest) Encrypted() bool {
	return strings.HasSuffix(m.Image.GetEdition(), "encrypted-lab")
}

// serves reports whether the manifest's image can boot a lane of this kind.
// A debian-installer netinst ISO is both: the lab installs the plain golden
// for cloud lanes and the guided-LUKS golden for encrypted lanes from it.
func (m *Manifest) serves(kind labv1.MatrixImage) bool {
	netinst := m.Release.Lab.Installer == platform.DebianInstaller && m.Image.GetEdition() == "netinst"
	if kind == labv1.MatrixImage_MATRIX_IMAGE_ENCRYPTED_INSTALLER {
		return m.Encrypted() || netinst
	}
	return !m.Encrypted()
}

// Cell is one (platform, cell, architecture) of the matrix.
type Cell struct {
	Release      *platform.Release
	Spec         *labv1.MatrixCell
	Architecture string
	// Manifest is the image the lane boots; nil when none is pinned.
	Manifest *Manifest
	// Recovery is the same-release cloud image a device-action lane recovers
	// into; nil when none is pinned.
	Recovery *Manifest
	State    State
	// Reason explains gated and no-lane states.
	Reason string
	// Entry is the latest ledger entry, if any.
	Entry *labv1.MatrixLedgerEntry
	// Kinds are the implemented capabilities a capability_kinds cell passes.
	Kinds []platform.Capability
}

// Runnable reports whether the cell has a lane, an image and no gate.
func (c *Cell) Runnable() bool {
	return c.State != Gated && c.State != NoLane && c.State != NoImage
}

// RequalificationDue reports whether a rolling cell lacks a current, complete
// pass for its exact snapshot. Gated cells remain visible to the scheduler.
func (c *Cell) RequalificationDue(now time.Time) bool {
	days := c.Release.Native().RequalificationDays
	if days == 0 {
		return false
	}
	e := c.Entry
	if c.State != Pass || e == nil || e.GetScope() != "" {
		return true
	}
	recorded := e.GetRecorded().AsTime()
	return recorded.After(now) || !now.Before(recorded.Add(time.Duration(days)*24*time.Hour))
}

// Inputs are the loaded declarative inputs of a plan.
type Inputs struct {
	// PreferredManifest is an explicit owner-selected image, never a guessed
	// boot topology. Otherwise rolling rows select the newest repository date.
	PreferredManifest string
	Matrix            *labv1.LabMatrix
	Manifests         []*Manifest
	Ledger            *labv1.MatrixLedger
}

// Load reads the matrix, image manifests and ledger under a repository root.
func Load(root string) (*Inputs, error) {
	matrix, err := LoadMatrix(filepath.Join(root, MatrixFile))
	if err != nil {
		return nil, err
	}
	manifests, err := LoadManifests(root)
	if err != nil {
		return nil, err
	}
	ledger, err := LoadLedger(filepath.Join(root, LedgerFile))
	if err != nil {
		return nil, err
	}
	return &Inputs{Matrix: matrix, Manifests: manifests, Ledger: ledger}, nil
}

// LoadMatrix strictly decodes and validates the cell table.
func LoadMatrix(path string) (*labv1.LabMatrix, error) {
	matrix := new(labv1.LabMatrix)
	if err := decode(path, matrix); err != nil {
		return nil, err
	}
	for _, cell := range matrix.GetCells() {
		for _, c := range cell.GetCapabilities() {
			if !slices.Contains(platform.Capabilities, platform.Capability(c)) {
				return nil, fmt.Errorf("lab matrix: cell %s names unknown capability %q", cell.GetName(), c)
			}
		}
	}
	for _, name := range matrix.GetRollingRequalificationCells() {
		if !slices.ContainsFunc(matrix.GetCells(), func(c *labv1.MatrixCell) bool { return c.GetName() == name }) {
			return nil, fmt.Errorf("lab matrix: rolling requalification names unknown cell %q", name)
		}
	}
	return matrix, nil
}

// LoadManifests decodes every pinned manifest under root's lab/images,
// identifying each with the registry.
func LoadManifests(root string) ([]*Manifest, error) {
	paths, err := filepath.Glob(filepath.Join(root, ImagesDir, "*.json"))
	if err != nil {
		return nil, err
	}
	out := make([]*Manifest, 0, len(paths))
	for _, path := range paths {
		image := new(labv1.ImageManifest)
		data, err := readBounded(path)
		if err != nil {
			return nil, err
		}
		if err := decodeBytes(path, data, image); err != nil {
			return nil, err
		}
		arch, ok := architecture(image.GetArchitecture())
		if !ok {
			return nil, fmt.Errorf("lab matrix: %s: unsupported architecture %q", path, image.GetArchitecture())
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil, err
		}
		out = append(out, &Manifest{Path: rel, Image: image, SHA256: fmt.Sprintf("%x", sha256.Sum256(data)), Release: platform.ForManifest(image.GetDistribution(), image.GetVersion()), Architecture: arch})
	}
	return out, nil
}

// LoadLedger strictly decodes the ledger; a missing ledger is empty.
func LoadLedger(path string) (*labv1.MatrixLedger, error) {
	ledger := new(labv1.MatrixLedger)
	if err := decode(path, ledger); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return ledger, nil
}

func decode(path string, m proto.Message) error {
	data, err := readBounded(path)
	if err != nil {
		return err
	}
	return decodeBytes(path, data, m)
}

func decodeBytes(path string, data []byte, m proto.Message) error {
	if err := protojson.Unmarshal(data, m); err != nil {
		return fmt.Errorf("lab matrix: decode %s: %w", path, err)
	}
	if err := protovalidate.Validate(m); err != nil {
		return fmt.Errorf("lab matrix: validate %s: %w", path, err)
	}
	return nil
}

func readBounded(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxFileBytes {
		return nil, fmt.Errorf("lab matrix: %s must be a regular file of at most %d bytes", path, maxFileBytes)
	}
	return os.ReadFile(path)
}

// architecture maps manifest spellings to the registry's.
func architecture(s string) (string, bool) {
	switch s {
	case "x86_64", "amd64":
		return "x86_64", true
	case "aarch64", "arm64":
		return "aarch64", true
	default:
		return "", false
	}
}

// Platforms returns the selected registry rows: every Tier 1/2 row when keys
// is empty, otherwise the named rows in the given order.
func Platforms(keys []string) ([]*platform.Release, error) {
	if len(keys) == 0 {
		var out []*platform.Release
		for _, r := range platform.Releases() {
			if r.Tier == platform.Tier1 || r.Tier == platform.Tier2 {
				out = append(out, r)
			}
		}
		return out, nil
	}
	out := make([]*platform.Release, 0, len(keys))
	for _, key := range keys {
		r, ok := platform.Lookup(key)
		if !ok {
			return nil, fmt.Errorf("lab matrix: unknown platform %q", key)
		}
		out = append(out, r)
	}
	return out, nil
}

// Cells selects matrix cells by name, all when names is empty.
func (in *Inputs) Cells(names []string) ([]*labv1.MatrixCell, error) {
	if len(names) == 0 {
		return in.Matrix.GetCells(), nil
	}
	out := make([]*labv1.MatrixCell, 0, len(names))
	for _, name := range names {
		i := slices.IndexFunc(in.Matrix.GetCells(), func(c *labv1.MatrixCell) bool { return c.GetName() == name })
		if i < 0 {
			return nil, fmt.Errorf("lab matrix: unknown cell %q", name)
		}
		out = append(out, in.Matrix.GetCells()[i])
	}
	return out, nil
}

// Plan expands releases × cells × each release's architectures and derives
// every cell's state.
func (in *Inputs) Plan(releases []*platform.Release, specs []*labv1.MatrixCell) []*Cell {
	var cells []*Cell
	for _, r := range releases {
		for _, spec := range specs {
			for _, arch := range r.Architectures {
				cells = append(cells, in.cell(r, spec, arch))
			}
		}
	}
	return cells
}

func (in *Inputs) cell(r *platform.Release, spec *labv1.MatrixCell, arch string) *Cell {
	c := &Cell{Release: r, Spec: spec, Architecture: arch}
	var reasons []string
	for _, name := range spec.GetCapabilities() {
		capability := platform.Capability(name)
		if reason := r.GateReason(capability); reason != "" {
			reasons = appendUnique(reasons, reason)
			continue
		}
		c.Kinds = append(c.Kinds, capability)
	}
	gated := len(reasons) > 0
	if spec.GetCapabilityKinds() {
		gated = len(c.Kinds) == 0
	}
	c.Manifest = in.manifest(r, spec.GetImage(), arch)
	if spec.GetImage() == labv1.MatrixImage_MATRIX_IMAGE_ENCRYPTED_INSTALLER {
		c.Recovery = in.manifest(r, labv1.MatrixImage_MATRIX_IMAGE_CLOUD, arch)
	}
	c.Entry = in.latest(c)
	switch laneGate := r.LaneGateOn(platform.LabLane(spec.GetLane()), arch); {
	case gated:
		c.State, c.Reason = Gated, strings.Join(reasons, "; ")
	case laneGate != "":
		c.State, c.Reason = Gated, laneGate
	case spec.GetLane() == "":
		c.State, c.Reason = NoLane, spec.GetNoLane()
	case slices.Contains(platform.LabLanes, platform.LabLane(spec.GetLane())) && r.LabLaneOn(platform.LabLane(spec.GetLane()), arch) != nil:
		c.State, c.Reason = NoLane, r.LabLaneOn(platform.LabLane(spec.GetLane()), arch).Error()
	case c.Manifest == nil:
		c.State = NoImage
	case c.Entry == nil:
		c.State = NotRun
	case c.Entry.GetVerdict() == labv1.MatrixVerdict_MATRIX_VERDICT_PASS:
		c.State = Pass
	default:
		c.State = Fail
	}
	return c
}

// manifest selects the explicit owner choice, otherwise the newest pinned
// repository date for rolling releases. Fixed releases retain path ordering.
func (in *Inputs) manifest(r *platform.Release, kind labv1.MatrixImage, arch string) *Manifest {
	var selected *Manifest
	for _, m := range in.Manifests {
		if m.Release.Key != r.Key || m.Architecture != arch || !m.serves(kind) {
			continue
		}
		if m.Image.GetId() == in.PreferredManifest {
			return m
		}
		if selected == nil || (r.Native().RequalificationDays != 0 && m.Image.GetRepositorySnapshotDate() > selected.Image.GetRepositorySnapshotDate()) {
			selected = m
		}
	}
	return selected
}

// latest returns the newest entry for the cell's exact rolling snapshot.
// Legacy fixed-release imports retain their historical scope.
func (in *Inputs) latest(c *Cell) *labv1.MatrixLedgerEntry {
	var out *labv1.MatrixLedgerEntry
	for _, e := range in.Ledger.GetEntries() {
		if e.GetPlatform() != c.Release.Key || e.GetCell() != c.Spec.GetName() || e.GetArchitecture() != c.Architecture {
			continue
		}
		if c.Release.Native().RequalificationDays != 0 && (c.Manifest == nil ||
			e.GetManifest() != c.Manifest.Image.GetId() || e.GetManifestSha256() != c.Manifest.SHA256 ||
			e.GetRepositorySnapshotDate() != c.Manifest.Image.GetRepositorySnapshotDate()) {
			continue
		}
		if out == nil || !e.GetRecorded().AsTime().Before(out.GetRecorded().AsTime()) {
			out = e
		}
	}
	return out
}

func appendUnique(list []string, s string) []string {
	if slices.Contains(list, s) {
		return list
	}
	return append(list, s)
}
