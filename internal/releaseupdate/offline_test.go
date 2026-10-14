// SPDX-License-Identifier: Apache-2.0

package releaseupdate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
	"google.golang.org/protobuf/proto"
)

func onlineSigners(signers RoleSigners) RoleSigners {
	return RoleSigners{Rollout: signers.Rollout, Snapshot: signers.Snapshot, Timestamp: signers.Timestamp}
}

func (f *repositoryFixture) exportOffline(t *testing.T, rings ...string) (string, *OfflineExport) {
	t.Helper()
	destination := filepath.Join(t.TempDir(), "export")
	export, err := ExportOffline(context.Background(), OfflineExportConfig{Source: f.directory, BootstrapRoot: f.root, Destination: destination, Rings: rings, Now: func() time.Time { return f.now }})
	if err != nil {
		t.Fatal(err)
	}
	return destination, export
}

func (f *repositoryFixture) importConfig(site, source string, export *OfflineExport, rings ...string) OfflineImportConfig {
	return OfflineImportConfig{Directory: site, Signers: onlineSigners(f.publisher.cfg.Signers), BootstrapRoot: f.root, Source: source, TargetsVersion: export.TargetsVersion, Rings: rings, Now: func() time.Time { return f.now }}
}

// publishPackage adds a new offline-authorized package to the station channel.
func (f *repositoryFixture) publishPackage(t *testing.T, version string, generation uint64) (string, []byte) {
	t.Helper()
	payload := []byte("offline station package " + version + "\n")
	source := filepath.Join(t.TempDir(), "lindm-agent.deb")
	mustWrite(t, source, payload)
	channel := proto.CloneOf(f.channel)
	channel.Generation = generation
	artifact := channel.Artifacts[0]
	artifact.Version, artifact.NativeVersion = version, version+"-1"
	artifact.TargetPath = "packages/lindm-agent/" + version + "/amd64.deb"
	if err := f.publisher.Publish(context.Background(), channel, map[string]string{artifact.TargetPath: source}); err != nil {
		t.Fatal(err)
	}
	return artifact.TargetPath, payload
}

func targetFile(name string, payload []byte) string {
	hash := sha256.Sum256(payload)
	return "targets/" + hashPath(name, hash[:])
}

func exportedFiles(t *testing.T, directory string) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(directory, func(name string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		relative, err := filepath.Rel(directory, name)
		files = append(files, filepath.ToSlash(relative))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(files)
	return files
}

func stageSelected(t *testing.T, client *Client, site string, payload []byte) *Selection {
	t.Helper()
	selection, err := client.Select(context.Background(), fixtureRequest())
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(filepath.Join(site, filepath.FromSlash(selection.TargetPath)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	}()
	destination := filepath.Join(t.TempDir(), "private", "agent.deb")
	if err = client.Stage(context.Background(), selection, source, destination); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mustRead(t, destination), payload) {
		t.Fatal("staged bytes differ from the station package")
	}
	return selection
}

func TestOfflineBundleRoundTripWithOnlineCustody(t *testing.T) {
	f := newRepositoryFixture(t)
	ctx := context.Background()
	source, export := f.exportOffline(t, "stable")
	if export.FirstRootVersion != 1 || export.RootVersion != 1 || !slices.Equal(export.Rings, []string{"stable"}) {
		t.Fatalf("export = %+v", export)
	}
	want := []string{"channels/stable.json", "metadata/1.root.json", fmt.Sprintf("metadata/%d.targets.json", export.TargetsVersion), targetFile(f.channel.Artifacts[0].TargetPath, f.payload)}
	slices.Sort(want)
	if got := exportedFiles(t, source); !slices.Equal(got, want) {
		t.Fatalf("export files = %v, want only public %v", got, want)
	}
	if !bytes.Equal(mustRead(t, filepath.Join(source, "metadata/1.root.json")), f.root) {
		t.Fatal("export changed the bootstrap root bytes")
	}

	site := filepath.Join(t.TempDir(), "site")
	online := onlineSigners(f.publisher.cfg.Signers)
	imported, err := ImportOffline(ctx, f.importConfig(site, source, export, "stable"))
	if err != nil {
		t.Fatal(err)
	}
	if imported.Unchanged || imported.RootVersion != 1 || imported.TargetsVersion != export.TargetsVersion || len(imported.Channels) != 1 {
		t.Fatalf("import = %+v", imported)
	}
	publisher, err := NewPublisher(PublisherConfig{Directory: site, Signers: online, Now: f.publisher.cfg.Now})
	if err != nil {
		t.Fatal(err)
	}
	channel, err := publisher.Channel(ctx, "stable")
	if err != nil {
		t.Fatal(err)
	}
	if !channel.GetPaused() || channel.GetEligiblePercentage() != 0 || channel.GetGeneration() != 2 || !proto.Equal(channel, imported.Channels[0]) {
		t.Fatalf("imported channel = %v", channel)
	}
	if !proto.Equal(channel.GetArtifacts()[0], f.channel.GetArtifacts()[0]) {
		t.Fatal("imported proposal changed the offline artifact contract")
	}
	client := f.client(t, "", DirectoryFetch(site))
	if _, err = client.Select(ctx, fixtureRequest()); !errors.Is(err, ErrNoUpdate) {
		t.Fatalf("paused proposal selection = %v", err)
	}
	if _, err = publisher.SetRolloutRequest(ctx, "stable", false, 100, 2, "offline-unpause"); err != nil {
		t.Fatal(err)
	}
	stageSelected(t, client, site, f.payload)
}

func TestOfflineImportAdvancesAndRejectsRollback(t *testing.T) {
	f := newRepositoryFixture(t)
	ctx := context.Background()
	first, firstExport := f.exportOffline(t, "stable")
	site := filepath.Join(t.TempDir(), "site")
	if _, err := ImportOffline(ctx, f.importConfig(site, first, firstExport, "stable")); err != nil {
		t.Fatal(err)
	}
	// The running server keeps its own publisher; imports coordinate only through
	// the repository lock and on-disk state.
	server, err := NewPublisher(PublisherConfig{Directory: site, Signers: onlineSigners(f.publisher.cfg.Signers), Now: f.publisher.cfg.Now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = server.SetRolloutRequest(ctx, "stable", false, 100, 2, "first-rollout"); err != nil {
		t.Fatal(err)
	}

	name, payload := f.publishPackage(t, "1.2.4", 2)
	second, secondExport := f.exportOffline(t, "stable")
	if secondExport.TargetsVersion <= firstExport.TargetsVersion {
		t.Fatalf("station targets did not advance: %d -> %d", firstExport.TargetsVersion, secondExport.TargetsVersion)
	}
	imported, err := ImportOffline(ctx, f.importConfig(site, second, secondExport, "stable"))
	if err != nil {
		t.Fatal(err)
	}
	if imported.Unchanged || imported.TargetsVersion != secondExport.TargetsVersion || len(imported.Channels) != 1 {
		t.Fatalf("import = %+v", imported)
	}
	if proposal := imported.Channels[0]; !proposal.GetPaused() || proposal.GetGeneration() != 4 || proposal.GetArtifacts()[0].GetTargetPath() != name {
		t.Fatalf("proposal must supersede the site generation paused: %v", proposal)
	}
	timestamp := filepath.Join(site, "metadata/timestamp.json")
	before := mustRead(t, timestamp)

	replay, err := ImportOffline(ctx, f.importConfig(site, second, secondExport, "stable"))
	if err != nil {
		t.Fatal(err)
	}
	if !replay.Unchanged || replay.RootVersion != 1 || replay.TargetsVersion != secondExport.TargetsVersion || len(replay.Channels) != 0 || !bytes.Equal(before, mustRead(t, timestamp)) {
		t.Fatalf("replayed import committed: %+v", replay)
	}
	if _, err = ImportOffline(ctx, f.importConfig(site, first, firstExport, "stable")); !errors.Is(err, ErrOfflineRollback) {
		t.Fatalf("older export import = %v", err)
	}
	if !bytes.Equal(before, mustRead(t, timestamp)) {
		t.Fatal("rejected rollback changed the commit point")
	}

	// Same version, validly signed but different bytes: offline equivocation.
	forged := mustRead(t, filepath.Join(second, fmt.Sprintf("metadata/%d.targets.json", secondExport.TargetsVersion)))
	targets, err := metadata.Targets().FromBytes(forged)
	if err != nil {
		t.Fatal(err)
	}
	targets.Signed.Expires = targets.Signed.Expires.Add(-time.Hour)
	targets.Signatures = nil
	if _, err = targets.Sign(f.publisher.cfg.Signers.Targets[0]); err != nil {
		t.Fatal(err)
	}
	if forged, err = targets.ToBytes(false); err != nil {
		t.Fatal(err)
	}
	equivocation, _ := f.exportOffline(t)
	mustWrite(t, filepath.Join(equivocation, fmt.Sprintf("metadata/%d.targets.json", secondExport.TargetsVersion)), forged)
	if _, err = ImportOffline(ctx, f.importConfig(site, equivocation, secondExport)); err == nil || errors.Is(err, ErrOfflineRollback) {
		t.Fatalf("equivocating targets import = %v", err)
	}

	tamperedName, tamperedPayload := f.publishPackage(t, "1.2.5", 3)
	third, thirdExport := f.exportOffline(t)
	mustWrite(t, filepath.Join(third, filepath.FromSlash(targetFile(tamperedName, tamperedPayload))), bytes.Repeat([]byte("x"), len(tamperedPayload)))
	if _, err = ImportOffline(ctx, f.importConfig(site, third, thirdExport)); err == nil {
		t.Fatal("tampered offline target imported")
	}
	if !bytes.Equal(before, mustRead(t, timestamp)) {
		t.Fatal("failed import changed the commit point")
	}
	if _, err = os.Lstat(filepath.Join(site, filepath.FromSlash(targetFile(tamperedName, tamperedPayload)))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("tampered target published: %v", err)
	}

	if _, err = server.SetRolloutRequest(ctx, "stable", false, 100, 4, "second-rollout"); err != nil {
		t.Fatal(err)
	}
	selection := stageSelected(t, f.client(t, "", DirectoryFetch(site)), site, payload)
	if selection.Artifact.GetVersion() != "1.2.4" {
		t.Fatalf("selected %s", selection.Artifact.GetVersion())
	}
}

func TestOfflineImportRejectsForeignAuthority(t *testing.T) {
	f := newRepositoryFixture(t)
	ctx := context.Background()
	source, export := f.exportOffline(t, "stable")
	foreign := fixtureSigners(t)
	foreignRoot := newRepositoryFixture(t).root
	forged, _ := f.exportOffline(t, "stable")
	forgedTargets := filepath.Join(forged, fmt.Sprintf("metadata/%d.targets.json", export.TargetsVersion))
	targets, err := metadata.Targets().FromBytes(mustRead(t, forgedTargets))
	if err != nil {
		t.Fatal(err)
	}
	targets.Signatures = nil
	if _, err = targets.Sign(foreign.Targets[0]); err != nil {
		t.Fatal(err)
	}
	data, err := targets.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, forgedTargets, data)

	cases := map[string]func(*OfflineImportConfig){
		"targets signed by a non-root key": func(cfg *OfflineImportConfig) { cfg.Source = forged },
		"site rollout custody outside the offline delegation": func(cfg *OfflineImportConfig) {
			cfg.Signers.Rollout = foreign.Rollout
		},
		"site snapshot custody outside the root": func(cfg *OfflineImportConfig) { cfg.Signers.Snapshot = foreign.Snapshot },
		"offline targets custody on the site":    func(cfg *OfflineImportConfig) { cfg.Signers.Targets = f.publisher.cfg.Signers.Targets },
		"offline root custody on the site":       func(cfg *OfflineImportConfig) { cfg.Signers.Root = f.publisher.cfg.Signers.Root },
		"expired offline targets": func(cfg *OfflineImportConfig) {
			cfg.Now = func() time.Time { return f.now.Add(8 * 24 * time.Hour) }
		},
		"manifest names another targets version": func(cfg *OfflineImportConfig) { cfg.TargetsVersion++ },
		"proposal absent from the export":        func(cfg *OfflineImportConfig) { cfg.Rings = []string{"beta"} },
		"foreign bootstrap root":                 func(cfg *OfflineImportConfig) { cfg.BootstrapRoot = foreignRoot },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			site := filepath.Join(t.TempDir(), "site")
			cfg := f.importConfig(site, source, export, "stable")
			change(&cfg)
			if _, err := ImportOffline(ctx, cfg); err == nil {
				t.Fatal("import accepted")
			}
			if _, err := os.Lstat(filepath.Join(site, "metadata/timestamp.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("rejected import published metadata: %v", err)
			}
		})
	}
}

func TestOfflineImportCarriesRootRotation(t *testing.T) {
	f := newRepositoryFixture(t)
	ctx := context.Background()
	first, firstExport := f.exportOffline(t, "stable")
	site := filepath.Join(t.TempDir(), "site")
	if _, err := ImportOffline(ctx, f.importConfig(site, first, firstExport, "stable")); err != nil {
		t.Fatal(err)
	}
	previous := onlineSigners(f.publisher.cfg.Signers)
	next := fixtureSigners(t)
	if err := f.publisher.RotateRoot(ctx, next); err != nil {
		t.Fatal(err)
	}
	rotated, export := f.exportOffline(t)
	if export.FirstRootVersion != 1 || export.RootVersion != 2 {
		t.Fatalf("export = %+v", export)
	}
	timestamp := filepath.Join(site, "metadata/timestamp.json")
	before := mustRead(t, timestamp)
	cfg := f.importConfig(site, rotated, export)
	cfg.Signers = previous
	if _, err := ImportOffline(ctx, cfg); err == nil {
		t.Fatal("rotated-away online custody accepted")
	}
	if !bytes.Equal(before, mustRead(t, timestamp)) {
		t.Fatal("rejected import changed the commit point")
	}
	imported, err := ImportOffline(ctx, f.importConfig(site, rotated, export))
	if err != nil {
		t.Fatal(err)
	}
	if imported.RootVersion != 2 || imported.TargetsVersion != export.TargetsVersion {
		t.Fatalf("import = %+v", imported)
	}
	if !bytes.Equal(mustRead(t, filepath.Join(site, "metadata/root.json")), mustRead(t, filepath.Join(rotated, "metadata/2.root.json"))) {
		t.Fatal("site root alias did not advance to the rotated root")
	}
	publisher, err := NewPublisher(PublisherConfig{Directory: site, Signers: onlineSigners(next), Now: f.publisher.cfg.Now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = publisher.SetRolloutRequest(ctx, "stable", false, 100, 2, "post-rotation"); err != nil {
		t.Fatal(err)
	}
	stageSelected(t, f.client(t, "", DirectoryFetch(site)), site, f.payload)
}

func TestOfflineExportVerifiesSourceAndCleansUp(t *testing.T) {
	f := newRepositoryFixture(t)
	ctx := context.Background()
	scratch := t.TempDir()
	destination := filepath.Join(t.TempDir(), "export")
	t.Setenv("TMPDIR", scratch)
	cfg := OfflineExportConfig{Source: f.directory, BootstrapRoot: f.root, Destination: destination, Rings: []string{"beta"}, Now: func() time.Time { return f.now }}
	if _, err := ExportOffline(ctx, cfg); err == nil {
		t.Fatal("ring absent from the verified rollout role exported")
	}
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed export left destination: %v", err)
	}
	cfg.Rings = []string{"stable"}
	cfg.Now = func() time.Time { return f.now.Add(2 * 24 * time.Hour) }
	if _, err := ExportOffline(ctx, cfg); err == nil {
		t.Fatal("stale station timestamp exported")
	}
	cfg.Now = func() time.Time { return f.now }
	mustWrite(t, filepath.Join(f.directory, filepath.FromSlash(targetFile(f.channel.Artifacts[0].TargetPath, f.payload))), bytes.Repeat([]byte("x"), len(f.payload)))
	if _, err := ExportOffline(ctx, cfg); err == nil {
		t.Fatal("tampered station target exported")
	}
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed export left destination: %v", err)
	}
	entries, err := os.ReadDir(scratch)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("export left private verification state: %v", entries)
	}
	if err = os.Mkdir(destination, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(destination, "operator-file")
	mustWrite(t, marker, []byte("keep"))
	if _, err = ExportOffline(ctx, cfg); err == nil {
		t.Fatal("existing destination reused")
	}
	if !bytes.Equal(mustRead(t, marker), []byte("keep")) {
		t.Fatal("refused export removed an existing destination")
	}
}
