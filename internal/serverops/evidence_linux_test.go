// SPDX-License-Identifier: Apache-2.0

package serverops

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	configv1 "lindm/gen/lindm/config/v1"
)

func TestBackupEvidenceRequiresOriginalConfigurationIdentity(t *testing.T) {
	cfg := &configv1.ServerConfig{DeploymentId: "a9dff5b8-966d-4bbd-a568-b613bc0d056e", PublicUrl: "https://admin.example.invalid", DevicePublicUrl: proto.String("https://devices.example.invalid")}
	identity, err := NewBackupIdentity(cfg)
	if err != nil {
		t.Fatal(err)
	}
	completed := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	prior := BackupHealth{Identity: identity, LastCompleted: completed, Encrypted: true, Verified: true, Artifact: "lindmd-existing.tar.age"}
	if !BackupHealthMatches(prior, identity) {
		t.Fatal("matching original configuration rejected")
	}
	same := beginBackupHealth(prior, identity, completed.Add(time.Minute))
	if same.LastCompleted != completed || same.Artifact != prior.Artifact {
		t.Fatal("same deployment completion lost")
	}
	changed := proto.CloneOf(cfg)
	changed.PublicUrl = "https://other.example.invalid"
	foreign, err := NewBackupIdentity(changed)
	if err != nil {
		t.Fatal(err)
	}
	if BackupHealthMatches(prior, foreign) || BackupHealthMatches(BackupHealth{}, identity) {
		t.Fatal("foreign or legacy record confirmed")
	}
	failed := beginBackupHealth(prior, foreign, completed.Add(time.Minute))
	if !failed.LastCompleted.IsZero() || failed.Encrypted || failed.Verified || failed.Artifact != "" || failed.Identity != foreign {
		t.Fatal("foreign completion was relabelled by a failed attempt")
	}
}

func TestSupportArchiveOmitsCanariesFromEveryFreeTextProjection(t *testing.T) {
	canary := "SUPPORT-SECRET-CANARY-95248f0f"
	backup := BackupHealth{LastCompleted: time.Now(), LastFailure: canary, Artifact: canary, Identity: BackupIdentity{DeploymentID: canary, PublicURL: canary, DevicePublicURL: canary, ConfigSHA256: canary}, Encrypted: true, Verified: true}
	release := ReleaseFeedHealth{InstalledVersion: canary, AvailableVersion: canary, AdvisoryIDs: []string{canary}, Verified: true}
	facts := supportFacts{CreatedAt: time.Now(), Version: supportVersion(canary), OS: "linux", Architecture: "amd64", Counts: map[string]int64{"devices": 7}, Backup: safeSupportBackup(backup), Release: safeSupportRelease(release)}
	path := filepath.Join(t.TempDir(), "support.tar")
	if err := writeSupport(path, facts); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	}()
	reader := tar.NewReader(file)
	seen := map[string]bool{}
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte(canary)) {
			t.Fatalf("canary leaked in %s", header.Name)
		}
		if header.Name != "manifest.json" && header.Name != "support.json" {
			t.Fatalf("unexpected raw collection %q", header.Name)
		}
		seen[header.Name] = true
	}
	if len(seen) != 2 {
		t.Fatal("missing omission manifest or allowlisted facts")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatal("support output not private")
	}
}

func TestRecoveryBindingUsesAuthoritativeNewerSnapshotAndIndependentRoot(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	root := sha256.Sum256([]byte("independently retained root"))
	oldHash := sha256.Sum256([]byte("old ciphertext"))
	currentHash := sha256.Sum256([]byte("complete current ciphertext"))
	old := archiveManifest{CapturedAt: now.Add(-time.Hour), Version: "0.1.1", DeploymentID: "a9dff5b8-966d-4bbd-a568-b613bc0d056e", PublicURL: "https://admin.example.invalid", DevicePublicURL: "https://devices.example.invalid"}
	current := old
	current.Version = "0.1.2"
	current.CapturedAt = now
	current.FencedAt = now
	current.ExecutionRootSHA256 = hex.EncodeToString(root[:])
	current.MinimumRecoveryEpoch = 7
	checkpoint := &agentv1.ServerRecoveryCheckpoint{DeploymentId: current.DeploymentID, PublicUrl: current.PublicURL, DevicePublicUrl: current.DevicePublicURL, PackageVersion: current.Version, CapturedAt: timestamppb.New(now), ArchiveSha256: currentHash[:], OriginalArchiveSha256: oldHash[:], ExecutionRootSha256: root[:], RecoveryEpoch: 8}
	if err := validateRecoveryBinding(checkpoint, root[:], old, current, oldHash[:], currentHash[:], "0.1.2"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"root", "archive", "origin", "epoch", "fence", "version"} {
		t.Run(name, func(t *testing.T) {
			changed := proto.CloneOf(checkpoint)
			candidate := current
			pin := root[:]
			switch name {
			case "root":
				other := sha256.Sum256([]byte("self asserted archive root"))
				pin = other[:]
			case "archive":
				changed.ArchiveSha256 = oldHash[:]
			case "origin":
				changed.DevicePublicUrl = "https://attacker.example.invalid"
			case "epoch":
				changed.RecoveryEpoch = 7
			case "fence":
				candidate.FencedAt = time.Time{}
			case "version":
				changed.PackageVersion = "0.1.1"
			}
			if err := validateRecoveryBinding(changed, pin, old, candidate, oldHash[:], currentHash[:], "0.1.2"); err == nil {
				t.Fatal("mismatched recovery evidence admitted")
			}
		})
	}
}

func TestCompositeCustodyConfirmationIncludesFreshDatabaseExport(t *testing.T) {
	originalHash := sha256.Sum256([]byte("source encrypted identity export"))
	freshHash := sha256.Sum256([]byte("fresh database encrypted identity export"))
	configHash := sha256.Sum256([]byte("current original config"))
	record := &agentv1.ServerRecoveryCustody{DeploymentId: "a9dff5b8-966d-4bbd-a568-b613bc0d056e", PublicUrl: "https://admin.example.invalid", DevicePublicUrl: "https://devices.example.invalid", ConfigSha256: configHash[:], IdentityBundleSha256: originalHash[:]}
	before, err := (proto.MarshalOptions{Deterministic: true}).Marshal(custodyExportSet(record))
	if err != nil {
		t.Fatal(err)
	}
	record.DatabaseCustody = &agentv1.ServerRecoveryDatabaseCustody{IdentityBundlePath: "/var/lib/lindmd-operations/database-custody/" + strings.Repeat("a", 64) + "/identities.age", IdentityBundleSha256: freshHash[:]}
	set := custodyExportSet(record)
	after, err := (proto.MarshalOptions{Deterministic: true}).Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(before) == sha256.Sum256(after) || len(set.GetExports()) != 2 {
		t.Fatal("old source acknowledgement clears fresh DB custody")
	}
	if set.GetExports()[0].GetKind() != agentv1.ServerRecoveryExportKind_SERVER_RECOVERY_EXPORT_KIND_CANONICAL_AUTHORITY || set.GetExports()[1].GetKind() != agentv1.ServerRecoveryExportKind_SERVER_RECOVERY_EXPORT_KIND_FRESH_DATABASE {
		t.Fatal("required export ordering is not canonical")
	}
	if bytes.Equal(after, originalHash[:]) || bytes.Equal(after, freshHash[:]) {
		t.Fatal("composite set mislabelled as file checksum")
	}
	record.External = true
	record.IdentityBundleSha256 = nil
	record.DatabaseCustody.External = true
	record.DatabaseCustody.IdentityBundleSha256 = nil
	record.DatabaseCustody.IdentityBundlePath = ""
	if len(custodyExportSet(record).GetExports()) != 0 {
		t.Fatal("explicit supplied off-host recipients create a generated export task")
	}
}

func TestSignedVersionComparisonIsNumericAndClosed(t *testing.T) {
	if value, err := compareVersion("0.10.0", "0.9.0"); err != nil || value != 1 {
		t.Fatalf("numeric ordering: %d %v", value, err)
	}
	for _, version := range []string{"", "v1.2.3", "1.02.3", "1.2", "1.2.3-private-secret", "999999999999999999999999.1.1"} {
		if _, err := compareVersion(version, "1.2.3"); err == nil {
			t.Fatalf("unclosed release version %q", version)
		}
	}
}
