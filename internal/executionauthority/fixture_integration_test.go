// SPDX-License-Identifier: Apache-2.0

//go:build integration

package executionauthority

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/testdb"
	"lindm/internal/trust"
)

type fixture struct {
	ctx       context.Context
	pool      *pgxpool.Pool
	conn      *pgx.Conn
	store     *Store
	authority *trust.Authority
	root      *agentv1.ExecutionRoot
	keys      []ed25519.PrivateKey
	bundle    *agentv1.BootstrapBundle
	cfg       Config
	actor     uuid.UUID
	now       time.Time
}

func newFixture(t *testing.T, rootVersion uint64) *fixture {
	t.Helper()
	pool, conn := testdb.Open(t)
	f := &fixture{ctx: t.Context(), pool: pool, conn: conn, actor: uuid.New()}
	if err := pool.QueryRow(f.ctx, "SELECT clock_timestamp()").Scan(&f.now); err != nil {
		t.Fatal(err)
	}
	var err error
	f.authority, err = trust.New()
	if err != nil {
		t.Fatal(err)
	}
	f.keys = []ed25519.PrivateKey{newKey(t), newKey(t)}
	f.root = &agentv1.ExecutionRoot{
		DeploymentId: uuid.NewString(), Version: rootVersion, Threshold: 2,
		NotBefore: timestamppb.New(f.now.Add(-time.Hour)), ExpiresAt: timestamppb.New(f.now.Add(24 * time.Hour)),
		Keys: []*agentv1.ExecutionKey{publicKey(t, f.keys[0]), publicKey(t, f.keys[1])},
	}
	f.bundle = &agentv1.BootstrapBundle{
		BundleId: uuid.NewString(), DeploymentId: f.root.GetDeploymentId(),
		EnrollmentOrigin: "https://admin.example", DeviceOrigin: "https://device.example",
		TransportCaPem:  caPEM(t, newKey(t), f.now, x509.ExtKeyUsageServerAuth),
		ConsoleCaPem:    caPEM(t, newKey(t), f.now, x509.ExtKeyUsageServerAuth),
		DeviceCaPem:     caPEM(t, newKey(t), f.now, x509.ExtKeyUsageClientAuth),
		ReleaseRootJson: releaseRoot(t, newKey(t), f.now.Add(24*time.Hour)),
		NotBefore:       timestamppb.New(f.now.Add(-time.Minute)), ExpiresAt: timestamppb.New(f.now.Add(12 * time.Hour)),
	}
	f.cfg = f.config(t, f.root, f.keys)
	f.cfg.TLSPublicKey = newKey(t).Public()
	if _, err := pool.Exec(f.ctx, "INSERT INTO principals (id,issuer,subject) VALUES ($1,'https://issuer.example',$2)", f.actor, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) open(t *testing.T) *Store {
	t.Helper()
	s, err := New(f.ctx, f.pool, f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.store = s
	return s
}

func (f *fixture) config(t *testing.T, root *agentv1.ExecutionRoot, keys []ed25519.PrivateKey) Config {
	t.Helper()
	encoded, err := protojson.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	bundle := proto.CloneOf(f.bundle)
	bundle.DeploymentId = root.GetDeploymentId()
	bundle.ExecutionRootVersion = root.GetVersion()
	digest := sha256.Sum256(encoded)
	bundle.ExecutionRootSha256 = digest[:]
	return Config{RootJSON: encoded, BootstrapEnvelope: f.sign(t, bundle, keys...), TLSPublicKey: f.cfg.TLSPublicKey}
}

func (f *fixture) sign(t *testing.T, message proto.Message, keys ...ed25519.PrivateKey) []byte {
	t.Helper()
	encoded, err := f.authority.Sign(f.ctx, message, keys...)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func (f *fixture) delegation(t *testing.T, root *agentv1.ExecutionRoot, version, epoch uint64, revoke bool) *agentv1.ExecutionDelegation {
	t.Helper()
	d := &agentv1.ExecutionDelegation{
		DeploymentId: root.GetDeploymentId(), RootVersion: root.GetVersion(), Version: version, MinimumRecoveryEpoch: epoch,
		NotBefore: timestamppb.New(f.now.Add(-time.Minute)), ExpiresAt: timestamppb.New(f.now.Add(6 * time.Hour)),
	}
	if !revoke {
		d.Delegates = []*agentv1.ExecutionDelegate{{Key: publicKey(t, newKey(t)), Role: agentv1.ExecutionSignerRole_EXECUTION_SIGNER_ROLE_PLAN, Capabilities: []string{"systemd.service.v1"}}}
	}
	return d
}

func (f *fixture) request(t *testing.T, root *agentv1.ExecutionRoot, keys []ed25519.PrivateKey, version, epoch uint64, revoke bool) *agentv1.UpdateExecutionTrustRequest {
	t.Helper()
	return &agentv1.UpdateExecutionTrustRequest{DelegationEnvelope: f.sign(t, f.delegation(t, root, version, epoch, revoke), keys...)}
}

func (f *fixture) rotate(t *testing.T, root *agentv1.ExecutionRoot, keys []ed25519.PrivateKey) (*agentv1.ExecutionRoot, []ed25519.PrivateKey, *agentv1.ExecutionRootTransition) {
	t.Helper()
	next := proto.CloneOf(root)
	next.Version++
	nextKeys := []ed25519.PrivateKey{newKey(t), newKey(t)}
	next.Keys = []*agentv1.ExecutionKey{publicKey(t, nextKeys[0]), publicKey(t, nextKeys[1])}
	transition := &agentv1.ExecutionRootTransition{PreviousQuorumEnvelope: f.sign(t, next, keys...), NextQuorumEnvelope: f.sign(t, next, nextKeys...)}
	return next, nextKeys, transition
}

func (f *fixture) apply(t *testing.T, s *Store, request *agentv1.UpdateExecutionTrustRequest, reason string) (*agentv1.UpdateExecutionTrustResponse, error) {
	t.Helper()
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(f.ctx) }()
	// Match the production lock order; directory authorization itself belongs to
	// identity's independent real-directory/PG regressions, not a fake here.
	if _, err := tx.Exec(f.ctx, "SELECT id FROM principals WHERE id=$1 FOR UPDATE", f.actor); err != nil {
		t.Fatal(err)
	}
	receipt, err := s.Apply(f.ctx, tx, request, f.actor, reason)
	if err != nil {
		return nil, err
	}
	return receipt, tx.Commit(f.ctx)
}

func (f *fixture) fetch(t *testing.T, s *Store, root *agentv1.ExecutionRoot, version, epoch uint64, envelope []byte) (*Snapshot, *agentv1.UpdateExecutionTrustRequest, error) {
	t.Helper()
	rootDigest, err := trust.ExecutionRootDigest(root)
	if err != nil {
		t.Fatal(err)
	}
	var delegationDigest []byte
	if version != 0 {
		digest := sha256.Sum256(envelope)
		delegationDigest = digest[:]
	}
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(f.ctx) }()
	return s.ForDevice(f.ctx, tx, root.GetVersion(), version, epoch, rootDigest[:], delegationDigest)
}

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func publicKey(t *testing.T, key ed25519.PrivateKey) *agentv1.ExecutionKey {
	t.Helper()
	public := ed25519.PublicKey(key[ed25519.SeedSize:])
	id, err := trust.KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	return &agentv1.ExecutionKey{KeyId: id, PublicKey: public}
}

func caPEM(t *testing.T, key ed25519.PrivateKey, now time.Time, usage x509.ExtKeyUsage) []byte {
	t.Helper()
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "isolated execution authority"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{usage},
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func releaseRoot(t *testing.T, key ed25519.PrivateKey, expires time.Time) []byte {
	t.Helper()
	root := metadata.Root(expires)
	public, err := metadata.KeyFromPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"root", "targets", "snapshot", "timestamp"} {
		if err := root.Signed.AddKey(public, role); err != nil {
			t.Fatal(err)
		}
	}
	signer, err := signature.LoadSignerVerifier(key, crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := root.Sign(signer); err != nil {
		t.Fatal(err)
	}
	encoded, err := root.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
