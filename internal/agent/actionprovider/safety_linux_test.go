//go:build linux

package actionprovider

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestSecretDescriptorSealsAndErasesAnonymousLockedPages(t *testing.T) {
	secret := []byte("memory-only-unlock-credential")
	handle, err := secretFile(secret)
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := unix.Dup(int(handle.file.Fd()))
	if err != nil {
		_ = handle.Close()
		t.Fatal(err)
	}
	observer := os.NewFile(uintptr(duplicate), "test-secret-observer")
	defer func() {
		if err := observer.Close(); err != nil {
			t.Error(err)
		}
	}()
	var stat unix.Stat_t
	if err := unix.Fstat(int(handle.file.Fd()), &stat); err != nil {
		_ = handle.Close()
		t.Fatal(err)
	}
	if stat.Nlink != 0 {
		_ = handle.Close()
		t.Fatal("secret has a filesystem link")
	}
	seals, err := unix.FcntlInt(handle.file.Fd(), unix.F_GET_SEALS, 0)
	if err != nil {
		_ = handle.Close()
		t.Fatal(err)
	}
	required := unix.F_SEAL_FUTURE_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if seals&required != required {
		_ = handle.Close()
		t.Fatal("descriptor is not sealed against native helper writes")
	}
	if _, err := handle.file.WriteAt([]byte("X"), 0); !errors.Is(err, unix.EPERM) {
		_ = handle.Close()
		t.Fatalf("helper can alter unlock bytes: %v", err)
	}
	readback := make([]byte, len(secret))
	if _, err := observer.ReadAt(readback, 0); err != nil || !bytes.Equal(readback, secret) {
		_ = handle.Close()
		t.Fatalf("native reader lost credential: %v", err)
	}
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := observer.ReadAt(readback, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(readback, make([]byte, len(secret))) {
		t.Fatal("anonymous secret pages were not erased before unlocking")
	}
}

func TestNativeOutputLimitRejectsRatherThanTruncatesEvidence(t *testing.T) {
	var output boundedOutput
	if _, err := output.Write(bytes.Repeat([]byte{'x'}, outputLimit)); err != nil {
		t.Fatal(err)
	}
	if _, err := output.Write([]byte("more")); err == nil || !output.overflow || output.Len() != outputLimit {
		t.Fatal("oversized native evidence was accepted or expanded")
	}
}

func TestOfflineTargetRejectsRootStateMountSwapAndHolders(t *testing.T) {
	root, state := unix.Mkdev(8, 1), unix.Mkdev(8, 2)
	for _, variant := range []string{"root", "journal", "mounted-child", "swap-child", "holder", "safe"} {
		t.Run(variant, func(t *testing.T) {
			node := blockNode{Type: "disk", Device: "8:16", Children: []blockNode{{Type: "part", Device: "8:17"}}}
			switch variant {
			case "root":
				node.Children[0].Device = "8:1"
			case "journal":
				node.Children[0].Device = "8:2"
			case "mounted-child":
				mount := "/home"
				node.Children[0].Mountpoints = []*string{&mount}
			case "swap-child":
				node.Children[0].Filesystem = "swap"
			}
			err := checkOfflineTree(node, state, root, func(string) (bool, error) { return variant == "holder", nil })
			if (err == nil) != (variant == "safe") {
				t.Fatalf("qualification %s: %v", variant, err)
			}
		})
	}
	if !encryptedTree(blockNode{Children: []blockNode{{Filesystem: "crypto_LUKS"}}}) {
		t.Fatal("encrypted partition disappeared behind whole-disk target")
	}
}

func TestHeaderExtentRequiresBothHeadersAndCompleteBoundedLayout(t *testing.T) {
	for _, variant := range []string{"valid", "secondary", "oversized", "detached", "version"} {
		t.Run(variant, func(t *testing.T) {
			file, err := os.CreateTemp(t.TempDir(), "luks-header-fixture-")
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := file.Close(); err != nil {
					t.Error(err)
				}
			}()
			if err := file.Truncate(32 << 20); err != nil {
				t.Fatal(err)
			}
			primary, secondary := make([]byte, 4096), make([]byte, 4096)
			copy(primary, []byte{'L', 'U', 'K', 'S', 0xba, 0xbe})
			copy(secondary, []byte{'S', 'K', 'U', 'L', 0xba, 0xbe})
			binary.BigEndian.PutUint16(primary[6:8], 2)
			binary.BigEndian.PutUint16(secondary[6:8], 2)
			binary.BigEndian.PutUint64(primary[8:16], 16384)
			binary.BigEndian.PutUint64(secondary[8:16], 16384)
			offset := "16777216"
			switch variant {
			case "secondary":
				secondary[0] = 0
			case "oversized":
				offset = "268435456"
			case "detached":
				offset = "0"
			case "version":
				binary.BigEndian.PutUint16(primary[6:8], 1)
			}
			if _, err := file.WriteAt(primary, 0); err != nil {
				t.Fatal(err)
			}
			if _, err := file.WriteAt(secondary, 16384); err != nil {
				t.Fatal(err)
			}
			metadata, err := parseMetadata([]byte(`{"keyslots":{},"tokens":{},"segments":{"0":{"type":"crypt","offset":"` + offset + `"}}}`))
			if err != nil {
				t.Fatal(err)
			}
			extent, err := luksHeaderExtent(file, metadata, 32<<20)
			if variant == "valid" {
				if err != nil || extent != 16<<20 {
					t.Fatalf("complete extent: %d %v", extent, err)
				}
			} else if err == nil {
				t.Fatal("unsafe header layout accepted")
			}
		})
	}
}

func TestInterruptedOverwriteAndFailedReadbackRemainUnverified(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sacrificial-file-not-a-native-device")
	if err := os.WriteFile(path, bytes.Repeat([]byte{0xaa}, 1<<20), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := overwriteRange(ctx, file, 1<<20); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled overwrite started effects")
	}
	var first [1]byte
	if _, err := file.ReadAt(first[:], 0); err != nil || first[0] != 0xaa {
		t.Fatal("canceled overwrite mutated file")
	}
	if err := verifyZeroSamples(context.Background(), file, 1<<20); !errors.Is(err, ErrNotVerified) {
		t.Fatalf("nonzero medium falsely verified: %v", err)
	}
	if err := overwriteRange(context.Background(), file, 1<<20); err != nil {
		t.Fatal(err)
	}
	if err := verifyZeroRange(context.Background(), file, 1<<20); err != nil {
		t.Fatal(err)
	}
	if err := verifyZeroSamples(context.Background(), file, 1<<20); err != nil {
		t.Fatal(err)
	}
	if err := verifyZeroRange(context.Background(), file, 2<<20); !errors.Is(err, io.EOF) {
		t.Fatalf("short read became successful proof: %v", err)
	}
}

func TestQuarantineFailedCheckpointRollsBackOwnedTable(t *testing.T) {
	for _, denyGate := range []bool{false, true} {
		applied, removed := false, false
		p := &Provider{config: &agentv1.DeviceActionProviderConfig{QuarantineSeconds: 30}}
		p.run = func(_ context.Context, request nativeRequest) ([]byte, error) {
			if request.command != nft {
				return nil, errors.New("unexpected native helper")
			}
			if len(request.args) > 2 && request.args[0] == "--json" && request.args[2] == "tables" {
				return []byte(`{"nftables":[]}`), nil
			}
			if request.args[0] == "--check" {
				return nil, nil
			}
			if request.args[0] == "--file" {
				applied = true
				return nil, nil
			}
			if request.args[0] == "delete" {
				removed = true
				return nil, nil
			}
			return nil, errors.New("native table observation interrupted")
		}
		plan := &agentv1.DeviceActionPlan{ActionId: fixtureAction, Spec: &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Quarantine{Quarantine: &agentv1.QuarantineAction{ManagementEndpoints: []string{"192.0.2.10"}}}}}
		gate := func(context.Context) error {
			if denyGate {
				return ErrConflict
			}
			return nil
		}
		err := p.applyQuarantine(context.Background(), plan, gate)
		if err == nil || applied != !denyGate || removed != !denyGate {
			t.Fatalf("checkpoint failure gate=%v applied=%v rollback=%v err=%v", denyGate, applied, removed, err)
		}
	}
}

func TestExpiredNativeSetDoesNotClaimQuarantineActive(t *testing.T) {
	p := &Provider{run: func(context.Context, nativeRequest) ([]byte, error) {
		return []byte(`{"nftables":[{"set":{"name":"active","type":"integer","flags":["timeout"],"elem":[]}},{"chain":{"hook":"input","policy":"accept"}},{"chain":{"hook":"output","policy":"accept"}},{"chain":{"hook":"forward","policy":"accept"}},{"rule":{"expr":[{"drop":null}]}},{"rule":{"expr":[{"drop":null}]}},{"rule":{"expr":[{"drop":null}]}}]}`), nil
	}}
	active, _, err := p.quarantineActive(context.Background(), "lindm_q_fixture")
	if err != nil || active {
		t.Fatalf("expired kernel set falsely reported restrictive: %v", err)
	}
}
