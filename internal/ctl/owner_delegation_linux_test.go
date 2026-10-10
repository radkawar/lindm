package ctl

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/trust"
)

const ownerTestID = "11111111-1111-4111-8111-111111111111"

type ownerFixture struct {
	dir         string
	now         time.Time
	authority   *trust.Authority
	verifier    *trust.ExecutionVerifier
	root        *agentv1.ExecutionRoot
	declaration *agentv1.ExecutionDelegation
	plan        ed25519.PrivateKey
	start       ed25519.PrivateKey
	args        []string
}

func ownerTestKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
}

func ownerPublic(t *testing.T, key ed25519.PrivateKey) *agentv1.ExecutionKey {
	t.Helper()
	public := ed25519.PublicKey(key[ed25519.SeedSize:])
	id, err := trust.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	return &agentv1.ExecutionKey{KeyId: id, PublicKey: public}
}

func ownerWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func ownerJSON(t *testing.T, message proto.Message) []byte {
	t.Helper()
	data, err := protojson.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func ownerSign(t *testing.T, authority *trust.Authority, message proto.Message, keys ...ed25519.PrivateKey) []byte {
	t.Helper()
	data, err := authority.Sign(t.Context(), message, keys...)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func newOwnerFixture(t *testing.T) ownerFixture {
	t.Helper()
	f := ownerFixture{dir: t.TempDir(), now: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC), plan: ownerTestKey(6), start: ownerTestKey(7)}
	// TempDir's numbered child follows the process umask; owner custody requires
	// exactly 0700 rather than accepting the usual 0755 test directory.
	if err := os.Chmod(f.dir, 0700); err != nil {
		t.Fatal(err)
	}
	var err error
	f.authority, err = trust.New()
	if err != nil {
		t.Fatal(err)
	}
	keys := []ed25519.PrivateKey{ownerTestKey(1), ownerTestKey(2)}
	f.root = &agentv1.ExecutionRoot{DeploymentId: ownerTestID, Version: 1, Threshold: 2, NotBefore: timestamppb.New(f.now.Add(-time.Hour)), ExpiresAt: timestamppb.New(f.now.Add(24 * time.Hour)), Keys: []*agentv1.ExecutionKey{ownerPublic(t, keys[0]), ownerPublic(t, keys[1])}}
	rootJSON := ownerJSON(t, f.root)
	digest := sha256.Sum256(rootJSON)
	ca := func(seed byte, usage x509.ExtKeyUsage) []byte {
		key := ownerTestKey(seed)
		cert := &x509.Certificate{SerialNumber: big.NewInt(int64(seed)), Subject: pkix.Name{CommonName: "offline owner test"}, NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(48 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		der, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	releaseKey := ownerTestKey(5)
	release := metadata.Root(f.now.Add(24 * time.Hour))
	public, err := metadata.KeyFromPublicKey(releaseKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"root", "targets", "snapshot", "timestamp"} {
		if err := release.Signed.AddKey(public, role); err != nil {
			t.Fatal(err)
		}
	}
	signer, err := signature.LoadSignerVerifier(releaseKey, crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := release.Sign(signer); err != nil {
		t.Fatal(err)
	}
	releaseJSON, err := release.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	bundle := &agentv1.BootstrapBundle{BundleId: ownerTestID, DeploymentId: ownerTestID, EnrollmentOrigin: "https://enroll.example", DeviceOrigin: "https://devices.example", TransportCaPem: ca(3, x509.ExtKeyUsageServerAuth), DeviceCaPem: ca(4, x509.ExtKeyUsageClientAuth), ExecutionRootVersion: 1, ExecutionRootSha256: digest[:], ReleaseRootJson: releaseJSON, NotBefore: timestamppb.New(f.now.Add(-time.Minute)), ExpiresAt: timestamppb.New(f.now.Add(time.Hour))}
	bootstrapEnvelope := ownerSign(t, f.authority, bundle, keys...)
	bootstrap, err := f.authority.VerifyBootstrap(t.Context(), rootJSON, bootstrapEnvelope, f.now)
	if err != nil {
		t.Fatal(err)
	}
	f.verifier, err = f.authority.NewExecutionVerifier(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	f.declaration = &agentv1.ExecutionDelegation{DeploymentId: ownerTestID, RootVersion: 1, Version: 8, MinimumRecoveryEpoch: 3, NotBefore: timestamppb.New(f.now.Add(-time.Minute)), ExpiresAt: timestamppb.New(f.now.Add(time.Hour)), Delegates: []*agentv1.ExecutionDelegate{
		{Key: ownerPublic(t, f.plan), Role: agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_PLAN, Capabilities: []string{"device.restart.v1", "device.shutdown.v1", "device.refresh-inventory.v1"}},
		{Key: ownerPublic(t, f.start), Role: agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_START, Capabilities: []string{"device.restart.v1", "device.shutdown.v1", "device.refresh-inventory.v1"}},
	}}
	ownerWrite(t, filepath.Join(f.dir, "root.json"), rootJSON)
	ownerWrite(t, filepath.Join(f.dir, "bootstrap.dsse"), bootstrapEnvelope)
	ownerWrite(t, filepath.Join(f.dir, "declaration.json"), ownerJSON(t, f.declaration))
	f.args = []string{"delegation", "sign", "-root", filepath.Join(f.dir, "root.json"), "-bootstrap", filepath.Join(f.dir, "bootstrap.dsse"), "-declaration", filepath.Join(f.dir, "declaration.json"), "-previous-version", "7", "-minimum-recovery-epoch", "3", "-out", filepath.Join(f.dir, "delegation.dsse")}
	for i, key := range keys {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(f.dir, fmt.Sprintf("owner-%d.pem", i))
		ownerWrite(t, path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
		f.args = append(f.args, "-signer", path)
	}
	return f
}

func (f ownerFixture) run(t *testing.T) ([]byte, string) {
	t.Helper()
	var out bytes.Buffer
	if err := runOwnerDelegation(t.Context(), f.args, &out, func() time.Time { return f.now }); err != nil {
		t.Fatal(err)
	}
	envelope, err := os.ReadFile(filepath.Join(f.dir, "delegation.dsse"))
	if err != nil {
		t.Fatal(err)
	}
	return envelope, out.String()
}

func TestOwnerDelegationProductionVerifier(t *testing.T) {
	f := newOwnerFixture(t)
	envelope, review := f.run(t)
	delegation, err := f.verifier.VerifyDelegation(t.Context(), f.root, envelope, 7, 3, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(delegation, f.declaration) {
		t.Fatal("signed delegation differs from explicit declaration")
	}
	for _, d := range delegation.GetDelegates() {
		if !strings.Contains(review, "Delegate: "+d.GetKey().GetKeyId()+"\n  Role: "+d.GetRole().String()+"\n") {
			t.Fatal("review omitted a delegate role")
		}
		for _, capability := range d.GetCapabilities() {
			if strings.Count(review, "  Capability: "+capability+"\n") != 2 {
				t.Fatal("review omitted or broadened selected capabilities")
			}
		}
	}
	if strings.Contains(review, "systemd.service.v1") || strings.Contains(review, "device.sanitize.v1") {
		t.Fatal("review added unrequested capabilities")
	}
	for _, spec := range []*agentv1.DeviceActionSpec{
		{Action: &agentv1.DeviceActionSpec_Restart{Restart: &agentv1.RestartAction{}}},
		{Action: &agentv1.DeviceActionSpec_Shutdown{Shutdown: &agentv1.ShutdownAction{}}},
		{Action: &agentv1.DeviceActionSpec_RefreshInventory{RefreshInventory: &agentv1.RefreshInventoryAction{}}},
	} {
		f.checkAction(t, delegation, spec, true)
	}
	stat, err := os.Stat(filepath.Join(f.dir, "delegation.dsse"))
	if err != nil || stat.Mode().Perm() != 0600 {
		t.Fatal("output did not retain private file permissions")
	}
	// A failed second publication cannot replace an already signed authority.
	var second bytes.Buffer
	if err := runOwnerDelegation(t.Context(), f.args, &second, func() time.Time { return f.now }); err == nil {
		t.Fatal("replaced existing signed output")
	}
	after, err := os.ReadFile(filepath.Join(f.dir, "delegation.dsse"))
	if err != nil || !bytes.Equal(after, envelope) {
		t.Fatal("existing signed authority changed")
	}
}

func (f ownerFixture) checkAction(t *testing.T, delegation *agentv1.ExecutionDelegation, spec *agentv1.DeviceActionSpec, allowed bool) {
	t.Helper()
	digest, err := trust.DeviceActionDigest(spec)
	if err != nil {
		t.Fatal(err)
	}
	intent := &agentv1.DeviceActionIntent{DeploymentId: ownerTestID, DeviceId: ownerTestID, EnrollmentGeneration: ownerTestID, ActionId: ownerTestID, ActorId: ownerTestID, ActionSequence: 1, RecoveryEpoch: 3, RootVersion: 1, DelegationVersion: 8, AuthorizationVersion: 2, NotBefore: timestamppb.New(f.now), ExpiresAt: timestamppb.New(f.now.Add(5 * time.Minute)), Spec: spec, SpecSha256: digest[:]}
	intentEnvelope := ownerSign(t, f.authority, intent, f.plan)
	_, err = f.verifier.VerifyDeviceActionIntent(t.Context(), f.root, delegation, intentEnvelope, f.now)
	if (err == nil) != allowed {
		t.Fatalf("plan admission = %v, want allowed=%v", err, allowed)
	}
	intentDigest := sha256.Sum256(intentEnvelope)
	plan := &agentv1.DeviceActionPlan{Spec: spec, ActionId: ownerTestID, Before: &agentv1.DeviceActionObservation{ObservedAt: timestamppb.New(f.now), Supported: true}}
	planDigest, err := trust.DeviceActionDigest(plan)
	if err != nil {
		t.Fatal(err)
	}
	challenge := &agentv1.DeviceActionChallenge{DeploymentId: ownerTestID, DeviceId: ownerTestID, EnrollmentGeneration: ownerTestID, ActionId: ownerTestID, ActionSequence: 1, RecoveryEpoch: 3, IntentSha256: intentDigest[:], SpecSha256: digest[:], NativePlanSha256: planDigest[:], NativePlan: plan, Nonce: bytes.Repeat([]byte{9}, 32), BootId: ownerTestID, ExecutorIncarnation: ownerTestID, IssuedAt: timestamppb.New(f.now), ExpiresAt: timestamppb.New(f.now.Add(30 * time.Second))}
	grant := &agentv1.DeviceActionStartGrant{Challenge: challenge, ActorId: ownerTestID, AuthorizationVersion: 2, RootVersion: 1, DelegationVersion: 8, NotBefore: timestamppb.New(f.now), ExpiresAt: timestamppb.New(f.now.Add(30 * time.Second))}
	_, err = f.verifier.VerifyDeviceActionStart(t.Context(), f.root, delegation, ownerSign(t, f.authority, grant, f.start), intent, challenge, f.now)
	if (err == nil) != allowed {
		t.Fatalf("start admission = %v, want allowed=%v", err, allowed)
	}
}

func TestOwnerDelegationOmissionNeverGrants(t *testing.T) {
	f := newOwnerFixture(t)
	for _, d := range f.declaration.Delegates {
		d.Capabilities = []string{"device.refresh-inventory.v1"}
	}
	ownerWrite(t, filepath.Join(f.dir, "declaration.json"), ownerJSON(t, f.declaration))
	envelope, review := f.run(t)
	delegation, err := f.verifier.VerifyDelegation(t.Context(), f.root, envelope, 7, 3, f.now)
	if err != nil {
		t.Fatal(err)
	}
	f.checkAction(t, delegation, &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_RefreshInventory{RefreshInventory: &agentv1.RefreshInventoryAction{}}}, true)
	f.checkAction(t, delegation, &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Restart{Restart: &agentv1.RestartAction{}}}, false)
	f.checkAction(t, delegation, &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_Shutdown{Shutdown: &agentv1.ShutdownAction{}}}, false)
	if strings.Contains(review, "device.restart.v1") || strings.Contains(review, "device.shutdown.v1") {
		t.Fatal("omitted power capabilities appeared in review")
	}
}

func TestOwnerDelegationRejectsInvalidAuthority(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*ownerFixture)
	}{
		{"wildcard", func(f *ownerFixture) { f.declaration.Delegates[0].Capabilities = []string{"device.*"} }},
		{"prefix", func(f *ownerFixture) { f.declaration.Delegates[0].Capabilities = []string{"device.restart"} }},
		{"unknown capability version", func(f *ownerFixture) { f.declaration.Delegates[0].Capabilities = []string{"device.restart.v2"} }},
		{"unknown capability", func(f *ownerFixture) { f.declaration.Delegates[0].Capabilities = []string{"script.arbitrary.v1"} }},
		{"missing capabilities", func(f *ownerFixture) { f.declaration.Delegates[0].Capabilities = nil }},
		{"duplicate capabilities", func(f *ownerFixture) {
			f.declaration.Delegates[0].Capabilities = []string{"device.restart.v1", "device.restart.v1"}
		}},
		{"missing role", func(f *ownerFixture) {
			f.declaration.Delegates[0].Role = agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_UNSPECIFIED
		}},
		{"root binding", func(f *ownerFixture) { f.declaration.RootVersion++ }},
		{"deployment binding", func(f *ownerFixture) { f.declaration.DeploymentId = "22222222-2222-4222-8222-222222222222" }},
		{"version rollback", func(f *ownerFixture) { f.declaration.Version = 7 }},
		{"epoch rollback", func(f *ownerFixture) { f.declaration.MinimumRecoveryEpoch = 2 }},
		{"expired", func(f *ownerFixture) { f.declaration.ExpiresAt = timestamppb.New(f.now) }},
		{"future", func(f *ownerFixture) { f.declaration.NotBefore = timestamppb.New(f.now.Add(time.Minute)) }},
		{"outlives root", func(f *ownerFixture) { f.declaration.ExpiresAt = timestamppb.New(f.now.Add(25 * time.Hour)) }},
		{"root as delegate", func(f *ownerFixture) { f.declaration.Delegates[0].Key = ownerPublic(t, ownerTestKey(1)) }},
		{"transport as delegate", func(f *ownerFixture) { f.declaration.Delegates[0].Key = ownerPublic(t, ownerTestKey(3)) }},
		{"key identity mismatch", func(f *ownerFixture) {
			f.declaration.Delegates[0].Key.PublicKey = ownerPublic(t, ownerTestKey(9)).PublicKey
		}},
		{"insufficient quorum", func(f *ownerFixture) { f.args = f.args[:len(f.args)-2] }},
		{"duplicate signer", func(f *ownerFixture) { f.args[len(f.args)-1] = f.args[len(f.args)-3] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newOwnerFixture(t)
			tc.change(&f)
			ownerWrite(t, filepath.Join(f.dir, "declaration.json"), ownerJSON(t, f.declaration))
			var out bytes.Buffer
			if err := runOwnerDelegation(t.Context(), f.args, &out, func() time.Time { return f.now }); err == nil {
				t.Fatal("invalid authority was signed and published")
			}
			if out.Len() != 0 {
				t.Fatal("invalid authority emitted a successful review")
			}
			if _, err := os.Stat(filepath.Join(f.dir, "delegation.dsse")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid authority created output")
			}
		})
	}
}

func TestOwnerDelegationPrivateKeySafety(t *testing.T) {
	for _, kind := range []string{"world readable", "symlink", "hardlink", "malformed", "extra PEM", "nonroot signer", "unknown declaration field", "malformed flag"} {
		t.Run(kind, func(t *testing.T) {
			f := newOwnerFixture(t)
			path := filepath.Join(f.dir, "owner-0.pem")
			secret, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "world readable":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink", "hardlink":
				alias := filepath.Join(f.dir, "alias.pem")
				if kind == "symlink" {
					err = os.Symlink(path, alias)
				} else {
					err = os.Link(path, alias)
				}
				if err != nil {
					t.Fatal(err)
				}
				f.args[len(f.args)-3] = alias
			case "malformed":
				ownerWrite(t, path, append([]byte("private-key-material-do-not-log\n"), secret...))
			case "extra PEM":
				ownerWrite(t, path, append(bytes.Clone(secret), secret...))
			case "nonroot signer":
				der, err := x509.MarshalPKCS8PrivateKey(f.plan)
				if err != nil {
					t.Fatal(err)
				}
				ownerWrite(t, path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
			case "unknown declaration field":
				ownerWrite(t, filepath.Join(f.dir, "declaration.json"), []byte(`{"private-key-material-do-not-log":"invalid"}`))
			case "malformed flag":
				f.args = append(f.args, "-previous-version", "private-key-material-do-not-log")
			}
			var out bytes.Buffer
			err = runOwnerDelegation(t.Context(), f.args, &out, func() time.Time { return f.now })
			if err == nil {
				t.Fatal("unsafe owner input accepted")
			}
			combined := out.String() + err.Error()
			for _, forbidden := range []string{string(secret), "-----BEGIN PRIVATE KEY-----", "private-key-material-do-not-log", base64.StdEncoding.EncodeToString(ownerTestKey(1)), base64.StdEncoding.EncodeToString(ownerTestKey(1).Seed())} {
				if strings.Contains(combined, forbidden) {
					t.Fatal("private input was disclosed in output or error")
				}
			}
			if _, err := os.Stat(filepath.Join(f.dir, "delegation.dsse")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("unsafe input created output")
			}
		})
	}
}

func TestOwnerDelegationRequiresExplicitCounters(t *testing.T) {
	for _, flag := range []string{"-previous-version", "-minimum-recovery-epoch"} {
		t.Run(flag, func(t *testing.T) {
			f := newOwnerFixture(t)
			for i, argument := range f.args {
				if argument == flag {
					f.args = append(f.args[:i], f.args[i+2:]...)
					break
				}
			}
			var out bytes.Buffer
			if err := runOwnerDelegation(t.Context(), f.args, &out, func() time.Time { return f.now }); err == nil {
				t.Fatal("omitted rollback counter silently defaulted")
			}
			if _, err := os.Stat(filepath.Join(f.dir, "delegation.dsse")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("missing counter created signed output")
			}
		})
	}
}

func TestOwnerDelegationExplicitRevocation(t *testing.T) {
	f := newOwnerFixture(t)
	f.declaration.Delegates = nil
	ownerWrite(t, filepath.Join(f.dir, "declaration.json"), ownerJSON(t, f.declaration))
	envelope, review := f.run(t)
	delegation, err := f.verifier.VerifyDelegation(t.Context(), f.root, envelope, 7, 3, f.now)
	if err != nil || len(delegation.GetDelegates()) != 0 || !strings.Contains(review, "revokes all online signer authority") {
		t.Fatal("explicit empty delegation did not revoke all authority")
	}
}

func TestOwnerDelegationRetainsExplicitSupportedCapabilities(t *testing.T) {
	f := newOwnerFixture(t)
	capabilities := []string{
		"systemd.service.v1", trust.OfflineEnrollmentCapability,
		"device.escrow-rotate.v1", "device.tpm2-bind.v1",
		"device.lock-sessions.v1", "device.release-lock.v1",
		"device.quarantine.v1", "device.release-quarantine.v1",
		"device.crypto-erase.v1", "device.sanitize.v1",
		"device.restart.v1", "device.shutdown.v1", "device.refresh-inventory.v1",
	}
	for _, delegate := range f.declaration.Delegates {
		delegate.Capabilities = capabilities
	}
	ownerWrite(t, filepath.Join(f.dir, "declaration.json"), ownerJSON(t, f.declaration))
	envelope, review := f.run(t)
	delegation, err := f.verifier.VerifyDelegation(t.Context(), f.root, envelope, 7, 3, f.now)
	if err != nil || !proto.Equal(delegation, f.declaration) {
		t.Fatal("explicit supported capabilities were dropped or changed")
	}
	for _, capability := range capabilities {
		if strings.Count(review, "  Capability: "+capability+"\n") != 2 {
			t.Fatal("review did not list the exact capability for each role")
		}
	}
	for _, key := range []ed25519.PrivateKey{ownerTestKey(1), ownerTestKey(2)} {
		for _, secret := range [][]byte{key, key.Seed(), []byte(base64.StdEncoding.EncodeToString(key)), []byte(base64.StdEncoding.EncodeToString(key.Seed()))} {
			if bytes.Contains(envelope, secret) || strings.Contains(review, string(secret)) {
				t.Fatal("successful publication disclosed an owner private key")
			}
		}
	}
}
