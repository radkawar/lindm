//go:build linux

package packaging

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestSignerHomeContentionPreservesAgent(t *testing.T) {
	requireNativeTools(t, "gpg", "gpgconf", "gpg-connect-agent", "createrepo_c")
	// Keep the native agent's Unix socket path below sockaddr_un's limit.
	work, err := os.MkdirTemp("", "pkg-lock-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(work); err != nil {
			t.Error(err)
		}
	})
	key, err := GenerateDevelopmentSigner(context.Background(), work)
	if err != nil {
		t.Fatal(err)
	}
	home, err := openPrivate(key.Home)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(home.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = home.Close()
		t.Fatal(err)
	}
	defer func() {
		if err := stopAgent(context.Background(), work, key.Home); err != nil {
			t.Error(err)
		}
		if err := home.Close(); err != nil {
			t.Error(err)
		}
	}()
	if _, _, err := runTool(context.Background(), work, toolCmd{Name: "gpg-connect-agent", Args: []string{"--homedir", key.Home, "/bye"}}); err != nil {
		t.Fatal(err)
	}
	output, _, err := runTool(context.Background(), work, toolCmd{Name: "gpgconf", Args: []string{"--homedir", key.Home, "--list-dirs", "agent-socket"}})
	if err != nil {
		t.Fatal(err)
	}
	socket := strings.TrimSpace(string(output))
	assertAgentReachable(t, socket)
	encoded, err := json.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"apt", "rpm", "rejection"} {
		t.Run(operation, func(t *testing.T) {
			out := filepath.Join(work, operation)
			if err := os.Mkdir(out, 0o700); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSignerHomeContentionChild$", "-test.count=1")
			child.Env = append(os.Environ(), "LINDM_SIGNER_CONTENTION_KEY="+string(encoded), "LINDM_SIGNER_CONTENTION_OUT="+out, "LINDM_SIGNER_CONTENTION_OPERATION="+operation)
			if output, err := child.CombinedOutput(); err != nil {
				t.Errorf("contending %s: %v\n%s", operation, err, output)
			}
			assertAgentReachable(t, socket)
			entries, err := os.ReadDir(out)
			if err != nil || len(entries) != 0 {
				t.Fatalf("contending operation left output: %v, %v", entries, err)
			}
		})
	}
}

func TestSignerHomeContentionChild(t *testing.T) {
	encoded := os.Getenv("LINDM_SIGNER_CONTENTION_KEY")
	if encoded == "" {
		return
	}
	var key SigningKey
	if err := json.Unmarshal([]byte(encoded), &key); err != nil {
		t.Fatal(err)
	}
	out := os.Getenv("LINDM_SIGNER_CONTENTION_OUT")
	// Absent artifacts are deliberate: the public operation must refuse
	// ownership before GPG validation, even if later artifact checks would fail.
	var err error
	switch os.Getenv("LINDM_SIGNER_CONTENTION_OPERATION") {
	case "apt":
		var result *APTRepository
		result, err = PublishAPT(context.Background(), APTRequest{
			DEBs: []string{filepath.Join(out, "missing.deb")}, OutputDir: out, Signer: key,
		})
		if result != nil {
			t.Fatalf("contending publication returned a result: %+v", result)
		}
	case "rpm":
		var result *RPMRepository
		result, err = PublishRPM(context.Background(), RPMRequest{
			RPMs: []string{filepath.Join(out, "missing.rpm")}, OutputDir: out, Signer: key,
		})
		if result != nil {
			t.Fatalf("contending publication returned a result: %+v", result)
		}
	case "rejection":
		var result *RejectionFixtures
		result, err = BuildRejectionFixtures(context.Background(), RejectionRequest{
			OutputDir: out, Signer: key, APT: &APTRepository{Custody: CustodyDevelopment},
		})
		if result != nil {
			t.Fatalf("contending fixtures returned a result: %+v", result)
		}
	default:
		t.Fatal("missing contention operation")
	}
	if !errors.Is(err, ErrSignerBusy) {
		t.Fatalf("want typed signer contention, got %v", err)
	}
}

func assertAgentReachable(t *testing.T, socket string) {
	t.Helper()
	conn, err := net.DialTimeout("unix", socket, time.Second)
	if err != nil {
		t.Fatalf("contending SDK operation stopped the lock owner's live GPG agent: %v", err)
	}
	_ = conn.Close()
}

func TestSignerGuardRetainsGeneratedHomeThroughCanceledCleanup(t *testing.T) {
	requireNativeTools(t, "gpg", "gpgconf", "gpg-connect-agent", "gpgv")
	work, err := os.MkdirTemp("", "pkg-guard-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(work); err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	key, guard, err := generateDevelopmentSigner(ctx, work)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := guard.close(context.Background(), work); err != nil {
			t.Error(err)
		}
	})
	// Generation's internal validation must retain the same inode lock rather
	// than releasing/reacquiring it or recursively acquiring another flock.
	assertSignerHomeLocked(t, key.Home)
	if _, contender, err := validateSigner(ctx, work, *key); !errors.Is(err, ErrSignerBusy) {
		if contender != nil {
			_ = contender.close(ctx, work)
		}
		t.Fatalf("generated signer was not exclusively owned: %v", err)
	}
	output, _, err := runTool(ctx, work, toolCmd{Name: "gpgconf", Args: []string{"--homedir", key.Home, "--list-dirs", "agent-socket"}})
	if err != nil {
		t.Fatal(err)
	}
	socket := strings.TrimSpace(string(output))
	assertAgentReachable(t, socket)

	// Independent homes must remain usable, including public key generation.
	other := filepath.Join(work, "other")
	if err := os.Mkdir(other, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateDevelopmentSigner(ctx, other); err != nil {
		t.Fatalf("independent signer generation blocked: %v", err)
	}
	assertAgentReachable(t, socket)
	if _, err := guard.validate(ctx, work, *key); err != nil {
		t.Fatal(err)
	}
	assertSignerHomeLocked(t, key.Home)
	assertAgentReachable(t, socket)

	payload := filepath.Join(work, "payload")
	signature := payload + ".asc"
	if err := os.WriteFile(payload, []byte("native signer ownership regression\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := runTool(ctx, work, toolCmd{
		Name: "gpg",
		Args: []string{"--no-options", "--batch", "--no-tty", "--pinentry-mode", "loopback", "--passphrase-file", key.PassphraseFile, "--homedir", key.Home, "--local-user", key.Fingerprint + "!", "--detach-sign", "--armor", "--output", signature, payload},
	}); err != nil {
		t.Fatal(err)
	}
	public, _, err := exportPublicKeys(ctx, work, *key, work)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := runTool(ctx, work, toolCmd{Name: "gpgv", Args: []string{"--keyring", public, signature, payload}}); err != nil {
		t.Fatalf("generated signer did not produce a valid native signature: %v", err)
	}
	assertSignerHomeLocked(t, key.Home)
	cancel()
	if err := guard.close(ctx, work); err != nil {
		t.Fatalf("canceled owner cleanup failed: %v", err)
	}
	assertAgentStopped(t, socket)
	released, err := openPrivate(key.Home)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = released.Close() }()
	if err := unix.Flock(int(released.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatalf("cleanup did not release signer-home ownership: %v", err)
	}
}

func assertSignerHomeLocked(t *testing.T, home string) {
	t.Helper()
	probe, err := openPrivate(home)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = probe.Close() }()
	if err := unix.Flock(int(probe.Fd()), unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatalf("signer-home directory inode is not exclusively locked: %v", err)
	}
}

func assertAgentStopped(t *testing.T, socket string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		conn, err := net.DialTimeout("unix", socket, time.Second)
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ECONNREFUSED) {
			return
		}
		if err != nil {
			t.Fatalf("checking native agent shutdown: %v", err)
		}
		_ = conn.Close()
		if time.Now().After(deadline) {
			t.Fatal("signing agent remains reachable after canceled owner cleanup")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSignerValidationFailureReleasesHome(t *testing.T) {
	requireNativeTools(t, "gpg", "gpgconf")
	work, err := os.MkdirTemp("", "pkg-invalid-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(work); err != nil {
			t.Error(err)
		}
	})
	key, err := GenerateDevelopmentSigner(context.Background(), work)
	if err != nil {
		t.Fatal(err)
	}
	key.Fingerprint = strings.Repeat("0", len(key.Fingerprint))
	if _, guard, err := validateSigner(context.Background(), work, *key); !errors.Is(err, ErrSigner) || guard != nil {
		if guard != nil {
			_ = guard.close(context.Background(), work)
		}
		t.Fatalf("real secret-key mismatch did not reject and release ownership: %v", err)
	}
	reacquired, err := lockSignerHome(key.Home, nil)
	if err != nil {
		t.Fatalf("failed validation retained its home lock: %v", err)
	}
	if err := reacquired.close(context.Background(), work); err != nil {
		t.Fatal(err)
	}
}
