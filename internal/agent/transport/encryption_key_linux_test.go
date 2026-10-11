//go:build linux

package transport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/gen/lindm/agent/v1/agentv1connect"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/gen/lindm/device/v1/devicev1connect"
)

// A management loop registers each certificate's key exactly once, stops
// calling anything once the root reports acknowledgment and re-registers only
// after renewal changes the certificate or the previous attempt failed.
func TestEncryptionKeyRegistersOncePerCertificate(t *testing.T) {
	root := &encryptionKeyRoot{certificate: bytes.Repeat([]byte{1}, sha256.Size)}
	server := &encryptionKeyServer{root: root}
	loop := root.loop(server)
	cycles := func(m *managementLoop, n int) {
		t.Helper()
		for range n {
			if err := m.registerEncryptionKey(t.Context(), root.connection()); err != nil {
				t.Fatal(err)
			}
		}
	}
	cycles(loop, 3)
	if server.registrations != 1 || root.prepares != 1 || root.acks != 1 {
		t.Fatalf("initial key: registrations=%d prepares=%d acks=%d", server.registrations, root.prepares, root.acks)
	}

	// Renewal installs a new certificate (and with it a new recipient key).
	root.certificate = bytes.Repeat([]byte{2}, sha256.Size)
	loop.cache.connection.CertificateSha256 = root.certificate
	cycles(loop, 3)
	if server.registrations != 2 || root.prepares != 2 || root.acks != 2 || !bytes.Equal(server.lastKey, root.publicKeySHA256()) {
		t.Fatalf("renewed key: registrations=%d prepares=%d acks=%d", server.registrations, root.prepares, root.acks)
	}

	// A restarted transport asks the root once; the durable acknowledgment
	// suppresses another network registration.
	cycles(root.loop(server), 3)
	if server.registrations != 2 || root.prepares != 3 {
		t.Fatalf("restart re-registered: registrations=%d prepares=%d", server.registrations, root.prepares)
	}

	// An unacknowledged failure is retried next cycle, never memoized.
	root.certificate = bytes.Repeat([]byte{3}, sha256.Size)
	loop.cache.connection.CertificateSha256 = root.certificate
	server.fail = true
	if err := loop.registerEncryptionKey(t.Context(), root.connection()); err == nil {
		t.Fatal("failed registration reported success")
	}
	server.fail = false
	cycles(loop, 2)
	if server.registrations != 4 || root.acks != 3 {
		t.Fatalf("failed registration not retried exactly once: registrations=%d acks=%d", server.registrations, root.acks)
	}
}

type encryptionKeyRoot struct {
	agentv1connect.ExecutorServiceClient
	certificate, acknowledged []byte
	prepares, acks            int
}

func (r *encryptionKeyRoot) loop(server devicev1connect.DeviceServiceClient) *managementLoop {
	return &managementLoop{
		executor: r, gate: make(authorityGate, 1),
		cache: connectionCache{connection: proto.CloneOf(r.connection()), servers: &connections{device: server}},
	}
}

func (r *encryptionKeyRoot) connection() *agentv1.GetConnectionResponse {
	return &agentv1.GetConnectionResponse{SessionEpoch: 1, SessionEpochUsable: true, RenewAfter: timestamppb.New(time.Now().Add(time.Hour)), CertificateSha256: bytes.Clone(r.certificate)}
}

// Each certificate carries its own recipient key, as renewal guarantees.
func (r *encryptionKeyRoot) publicKeySHA256() []byte {
	sum := sha256.Sum256(append([]byte("recipient"), r.certificate...))
	return sum[:]
}

func (r *encryptionKeyRoot) GetConnection(context.Context, *connect.Request[agentv1.GetConnectionRequest]) (*connect.Response[agentv1.GetConnectionResponse], error) {
	return connect.NewResponse(r.connection()), nil
}

func (*encryptionKeyRoot) PrepareSession(context.Context, *connect.Request[agentv1.PrepareSessionRequest]) (*connect.Response[agentv1.PrepareSessionResponse], error) {
	return connect.NewResponse(&agentv1.PrepareSessionResponse{Result: &agentv1.PrepareSessionResponse_Accepted{Accepted: &agentv1.AcceptedSession{SessionEpoch: 1}}}), nil
}

func (r *encryptionKeyRoot) PrepareEncryptionKey(context.Context, *connect.Request[agentv1.PrepareEncryptionKeyRequest]) (*connect.Response[agentv1.PrepareEncryptionKeyResponse], error) {
	r.prepares++
	return connect.NewResponse(&agentv1.PrepareEncryptionKeyResponse{
		AttestationEnvelope: append([]byte("attestation"), r.certificate...), PublicKeySha256: r.publicKeySHA256(),
		CertificateSha256: bytes.Clone(r.certificate), Acknowledged: bytes.Equal(r.acknowledged, r.certificate),
	}), nil
}

func (r *encryptionKeyRoot) AcknowledgeEncryptionKey(_ context.Context, req *connect.Request[agentv1.AcknowledgeEncryptionKeyRequest]) (*connect.Response[agentv1.AcknowledgeEncryptionKeyResponse], error) {
	if !bytes.Equal(req.Msg.GetPublicKeySha256(), r.publicKeySHA256()) || !bytes.Equal(req.Msg.GetCertificateSha256(), r.certificate) {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("encryption_key_stale"))
	}
	r.acks++
	r.acknowledged = bytes.Clone(r.certificate)
	return connect.NewResponse(&agentv1.AcknowledgeEncryptionKeyResponse{}), nil
}

type encryptionKeyServer struct {
	devicev1connect.DeviceServiceClient
	root          *encryptionKeyRoot
	registrations int
	fail          bool
	lastKey       []byte
}

func (s *encryptionKeyServer) RegisterEncryptionKey(_ context.Context, req *connect.Request[devicev1.RegisterEncryptionKeyRequest]) (*connect.Response[devicev1.RegisterEncryptionKeyResponse], error) {
	s.registrations++
	if s.fail {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("unavailable"))
	}
	if req.Msg.GetSessionEpoch() != 1 || !bytes.Equal(req.Msg.GetAttestationEnvelope(), append([]byte("attestation"), s.root.certificate...)) {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("authority_rejected"))
	}
	s.lastKey = s.root.publicKeySHA256()
	return connect.NewResponse(&devicev1.RegisterEncryptionKeyResponse{PublicKeySha256: s.lastKey, CertificateSha256: bytes.Clone(s.root.certificate)}), nil
}
