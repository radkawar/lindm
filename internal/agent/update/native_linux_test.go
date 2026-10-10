package update

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func TestNativeSuccessRequiresExactProductVersionArchitectureAndConfiguredState(t *testing.T) {
	tx := &agentv1.AgentUpdateTransaction{Version: "0.2.0", NativeVersion: "0.2.0-1", Architecture: "amd64", Manager: agentv1.NativeUpdateManager_NATIVE_UPDATE_MANAGER_APT}
	valid := installedPackage{name: "lindm-agent", version: "0.2.0-1", architecture: "amd64", state: "installed"}
	if err := valid.matchesTransaction(tx); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []installedPackage{
		{name: "lindmd", version: "0.2.0-1", architecture: "amd64", state: "installed"},
		{name: "lindm-agent", version: "0.1.0-1", architecture: "amd64", state: "installed"},
		{name: "lindm-agent", version: "0.2.0-2", architecture: "amd64", state: "installed"},
		{name: "lindm-agent", version: "0.2.0-1", architecture: "arm64", state: "installed"},
		{name: "lindm-agent", version: "0.2.0-1", architecture: "amd64", state: "install ok unpacked"},
		{name: "lindm-agent", version: "0.2.0-1", architecture: "amd64", state: "install ok half-configured"},
	} {
		if candidate.matchesTransaction(tx) == nil {
			t.Fatalf("false native success: %+v", candidate)
		}
	}
}

func TestUnrelatedAPTTransactionIsRefused(t *testing.T) {
	if err := ownedAPTPreview([]byte("Inst lindm-agent [0.1.0-1] (0.2.0-1 local [amd64])\nConf lindm-agent (0.2.0-1 local [amd64])\n")); err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{"Inst libc6 (2.99 local)\n", "Remv owner-package [1]\n", "Conf unrelated (1)\n", "Inst\n"} {
		if err := ownedAPTPreview([]byte(output)); err == nil {
			t.Fatalf("unrelated/ambiguous transaction accepted: %q", output)
		}
	}
}

func TestStagedPackageChangedAfterAdmissionIsRefused(t *testing.T) {
	directory := t.TempDir()
	data := []byte("exact TUF authenticated package bytes")
	digest := sha256.Sum256(data)
	tx := &agentv1.AgentUpdateTransaction{Manager: agentv1.NativeUpdateManager_NATIVE_UPDATE_MANAGER_APT, NativeVersion: "0.2.0", Architecture: "amd64", Length: uint64(len(data)), Sha256: hex.EncodeToString(digest[:])}
	path := packagePath(directory, tx)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyFile(path, tx); err != nil {
		t.Fatal(err)
	}
	data[0] ^= 1
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyFile(path, tx); err == nil {
		t.Fatal("same-length payload tampering survived helper re-verification")
	}
	if err := os.WriteFile(path, data[:len(data)-1], 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyFile(path, tx); err == nil {
		t.Fatal("truncated package survived helper re-verification")
	}
}

func TestExpiredStagingIsNotInterruptedNativeAuthority(t *testing.T) {
	now := time.Unix(1800000000, 0)
	tx := &agentv1.AgentUpdateTransaction{NativeVersion: "0.2.0-1", AdmittedAt: timestamppb.New(now.Add(-time.Minute)), VerifiedExpiresAt: timestamppb.New(now)}
	prior := installedPackage{version: "0.1.0-1", state: "installed"}
	if proof, err := expiryNeedsPredecessorProof(now.Add(-time.Second), tx, prior, ""); err != nil || proof {
		t.Fatalf("valid admission rejected: %t %v", proof, err)
	}
	if _, err := expiryNeedsPredecessorProof(now, tx, prior, ""); !errors.Is(err, errTransactionExpired) {
		t.Fatalf("expired first native effect accepted: %v", err)
	}
	if _, err := expiryNeedsPredecessorProof(now.Add(-2*time.Minute), tx, prior, ""); !errors.Is(err, errTransactionExpired) {
		t.Fatal("clock rollback revived first-effect authority")
	}
	if proof, err := expiryNeedsPredecessorProof(now, tx, prior, "installing"); err != nil || !proof {
		t.Fatal("an installing marker alone was treated as observed native effects")
	}
	prior.version = "0.2.0-1"
	if proof, err := expiryNeedsPredecessorProof(now, tx, prior, "installing"); err != nil || proof {
		t.Fatal("observed target database state could not recover")
	}
	if _, err := expiryNeedsPredecessorProof(now, tx, prior, ""); !errors.Is(err, errTransactionExpired) {
		t.Fatal("target version without consumed authority bypassed expiry")
	}
}

func TestNativeObservationErrorsDoNotInventAbsenceOrEffects(t *testing.T) {
	if !missingNativePackage("rpm", []byte("package lindm-agent is not installed\n"), "", 1) {
		t.Fatal("authoritative native absence not recognized")
	}
	if missingNativePackage("rpm", nil, "database corrupt", 1) || missingNativePackage("deb", nil, "permission denied", 1) {
		t.Fatal("failed native database query invented absence")
	}
	tx := &agentv1.AgentUpdateTransaction{Manager: agentv1.NativeUpdateManager_NATIVE_UPDATE_MANAGER_APT, Architecture: "amd64", NativeVersion: "0.2.0-1", PreviousNativeVersion: "0.1.0-1"}
	missing := installedPackage{name: "lindm-agent", state: "absent"}
	if recoverablePredecessor(missing, tx, "") || !recoverablePredecessor(missing, tx, "installing") {
		t.Fatal("missing native package did not require the durable installing boundary")
	}
	for _, output := range []string{"??5??????   /usr/libexec/lindm/lindm-agent\n", "missing     /usr/libexec/lindm/lindm-agent\n"} {
		if changed, _, err := verificationDifference([]byte(output)); err != nil || !changed {
			t.Fatalf("native payload divergence unrecognized: %q %v", output, err)
		}
	}
	if changed, conffiles, err := verificationDifference([]byte("??5?????? c /etc/lindm/executor.json\n")); err != nil || changed || !conffiles {
		t.Fatal("owner configuration was treated as interrupted executable state")
	}
	if changed, _, err := verificationDifference([]byte("error: database unavailable")); err == nil || changed {
		t.Fatal("diagnostic text invented native effects")
	}
}

func TestArchSignatureCustodyRejectsMissingSymlinkAndOversize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.pkg.tar.zst.sig")
	if err := protectedSignature(path); err == nil {
		t.Fatal("missing native signature accepted")
	}
	if err := os.WriteFile(path, []byte("bounded native signature"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := protectedSignature(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".real"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path+".real", path); err != nil {
		t.Fatal(err)
	}
	if err := protectedSignature(path); err == nil {
		t.Fatal("signature symlink accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, make([]byte, (64<<10)+1), 0600); err != nil {
		t.Fatal(err)
	}
	if err := protectedSignature(path); err == nil {
		t.Fatal("oversized signature accepted")
	}
}

type verificationExit int

func (e verificationExit) Error() string { return "native verification exit" }
func (e verificationExit) ExitCode() int { return int(e) }

func TestDPKGConffileOnlyExitRequiresStrictEvidence(t *testing.T) {
	conffile := []byte("??5?????? c /etc/lindm/executor.json\n")
	exitOne := &nativeFailure{program: "dpkg", cause: verificationExit(1)}
	if err := verificationResult(conffile, exitOne, true); err != nil {
		t.Fatal("owned conffile edit blocked installed binary verification:", err)
	}
	for _, test := range []struct {
		data []byte
		err  error
	}{
		{conffile, &nativeFailure{program: "dpkg", cause: verificationExit(2)}},
		{conffile, &nativeFailure{program: "dpkg", cause: verificationExit(1), stderr: "database error"}},
		{[]byte("garbage c /etc/lindm/executor.json\n"), exitOne},
		{[]byte("SSSSSSSSS c /etc/lindm/executor.json\n"), exitOne},
		{[]byte("??5?????? c not-an-absolute-path\n"), exitOne},
		{[]byte("??5??????   /usr/libexec/lindm/lindm-agent\n"), exitOne},
		{nil, exitOne},
	} {
		if err := verificationResult(test.data, test.err, true); err == nil {
			t.Fatal("failed/ambiguous native verification was accepted")
		}
	}
	if err := verificationResult(conffile, exitOne, false); err == nil {
		t.Fatal("dpkg conffile exception leaked into other native managers")
	}
}

func TestNativePackagePathMatchesPrivateAPTArchiveIdentity(t *testing.T) {
	for _, test := range []struct {
		manager             agentv1.NativeUpdateManager
		version, arch, name string
	}{
		{agentv1.NativeUpdateManager_NATIVE_UPDATE_MANAGER_APT, "0.2.0", "amd64", "lindm-agent_0.2.0_amd64.deb"},
		{agentv1.NativeUpdateManager_NATIVE_UPDATE_MANAGER_APT, "2:0.2.0~rc1+build-3", "arm64", "lindm-agent_2%3a0.2.0~rc1+build-3_arm64.deb"},
		{agentv1.NativeUpdateManager_NATIVE_UPDATE_MANAGER_APT, "0.2.0_custom", "amd64", "lindm-agent_0.2.0%5fcustom_amd64.deb"},
		{agentv1.NativeUpdateManager_NATIVE_UPDATE_MANAGER_DNF, "0.2.0-1", "amd64", "agent.rpm"},
		{agentv1.NativeUpdateManager_NATIVE_UPDATE_MANAGER_PACMAN, "0.2.0-1", "amd64", "agent.pkg.tar.zst"},
	} {
		tx := &agentv1.AgentUpdateTransaction{Manager: test.manager, NativeVersion: test.version, Architecture: test.arch}
		if got := packagePath("/private/transaction", tx); got != filepath.Join("/private/transaction", test.name) {
			t.Fatalf("native staged filename %q, want %q", got, test.name)
		}
	}
}
