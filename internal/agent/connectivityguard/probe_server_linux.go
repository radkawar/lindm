//go:build linux

package connectivityguard

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/pki"
	"lindm/internal/protodata"
	"lindm/internal/trust"
)

const ProbePath = "/lindm.device.v1.ConnectivityProbe/Exchange"

type probeJob struct {
	command               *agentv1.ConnectivityProbeCommand
	receiver              *packetReceiver
	receipt, readyReceipt []byte
	expires               time.Time
}

// ProbeServer is a separately installed external packet witness. Every destination
// and source is preapproved at startup; mTLS device identity authorizes access.
// At most 32 native sockets exist, all expire after ten seconds even if the
// controller/client disappears. Polling never waits for packet arrival.
type ProbeServer struct {
	mu                 sync.Mutex
	origin, deployment string
	targets            map[string]*agentv1.ConnectivityProbeTarget
	key                ed25519.PrivateKey
	authority          *trust.Authority
	rules              protovalidate.Validator
	jobs               map[string]*probeJob
	cancel             context.CancelFunc
	done               chan struct{}
	closeErr           error
	closed             bool
	slots              chan struct{}
}

func NewProbeServer(ctx context.Context, origin, deployment string, targets []*agentv1.ConnectivityProbeTarget, key ed25519.PrivateKey) (*ProbeServer, error) {
	if _, err := controllerAddress(origin); err != nil {
		return nil, err
	}
	if len(key) != ed25519.PrivateKeySize || deployment == "" || len(targets) == 0 || len(targets) > 32 {
		return nil, ErrConflict
	}
	authority, err := trust.New()
	if err != nil {
		return nil, err
	}
	rules, err := protovalidate.New(protovalidate.WithMessages(&agentv1.ConnectivityProbeCommand{}, &agentv1.ConnectivityProbeTarget{}))
	if err != nil {
		return nil, err
	}
	server := &ProbeServer{origin: origin, deployment: deployment, targets: make(map[string]*agentv1.ConnectivityProbeTarget, len(targets)), key: bytes.Clone(key), authority: authority, rules: rules, jobs: make(map[string]*probeJob), done: make(chan struct{}), slots: make(chan struct{}, 32)}
	for _, target := range targets {
		if err := rules.Validate(target); err != nil {
			return nil, err
		}
		if err := protodata.ValidateClosed(target.ProtoReflect()); err != nil {
			return nil, err
		}
		if _, _, err := packetAddresses(target); err != nil {
			return nil, err
		}
		if _, exists := server.targets[target.GetId()]; exists {
			return nil, ErrConflict
		}
		peer := target.GetSender()
		if target.GetReceiver().GetOrigin() == origin {
			peer = target.GetReceiver()
		}
		if public, ok := key.Public().(ed25519.PublicKey); !ok || peer.GetOrigin() != origin || !bytes.Equal(peer.GetPublicKey(), public) {
			return nil, ErrConflict
		}
		server.targets[target.GetId()] = proto.CloneOf(target)
	}
	ctx, server.cancel = context.WithCancel(ctx)
	go server.cleanup(ctx)
	return server, nil
}
func (s *ProbeServer) cleanup(ctx context.Context) {
	defer close(s.done)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			s.mu.Lock()
			s.closed = true
			for id, job := range s.jobs {
				if job.receiver != nil {
					s.closeErr = errors.Join(s.closeErr, job.receiver.close())
				}
				delete(s.jobs, id)
			}
			clear(s.key)
			s.mu.Unlock()
			return
		case <-ticker.C:
			s.mu.Lock()
			for id, job := range s.jobs {
				if !time.Now().Before(job.expires) {
					if job.receiver != nil {
						s.closeErr = errors.Join(s.closeErr, job.receiver.close())
					}
					delete(s.jobs, id)
				}
			}
			s.mu.Unlock()
		}
	}
}
func (s *ProbeServer) Close() error { s.cancel(); <-s.done; return s.closeErr }
func (s *ProbeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	reject := func(code int) { http.Error(w, "packet_witness_rejected", code) }
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		reject(http.StatusTooManyRequests)
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != ProbePath || r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/protobuf" {
		reject(http.StatusBadRequest)
		return
	}
	device, generation, ok := s.authenticateDevice(r)
	if !ok {
		reject(http.StatusUnauthorized)
		return
	}
	command, code := s.readCommand(w, r)
	if code != 0 {
		reject(code)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		reject(http.StatusServiceUnavailable)
		return
	}
	// Device identity is part of slot identity: another enrolled device cannot
	// observe, retransmit or release someone else's nonce/capture reservation.
	id := device.String() + "/" + generation.String() + "/" + command.GetPacket().GetActionId() + "/" + hex.EncodeToString(command.GetPacket().GetNonce())
	job := s.jobs[id]
	if job != nil && (!proto.Equal(job.command.GetPacket(), command.GetPacket()) || !proto.Equal(job.command.GetTarget(), command.GetTarget())) {
		reject(http.StatusConflict)
		return
	}
	response, code := s.operate(ctx, id, job, command)
	if code != 0 {
		reject(code)
		return
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(response)
	if err != nil {
		reject(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/protobuf")
	_, _ = w.Write(encoded)
}

// authenticateDevice accepts only a verified client certificate naming one
// currently valid device of this deployment.
func (s *ProbeServer) authenticateDevice(r *http.Request) (device, generation uuid.UUID, ok bool) {
	if r.TLS == nil || !r.TLS.HandshakeComplete || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return uuid.Nil, uuid.Nil, false
	}
	leaf := r.TLS.VerifiedChains[0][0]
	if len(leaf.URIs) != 1 {
		return uuid.Nil, uuid.Nil, false
	}
	deployment, device, generation, err := pki.ParseDeviceIdentity(leaf.URIs[0].String())
	if err != nil || deployment.String() != s.deployment || pki.CheckDeviceCertificate(leaf, deployment, device, generation) != nil {
		return uuid.Nil, uuid.Nil, false
	}
	return device, generation, true
}

// readCommand reads one bounded, closed and valid command for a preapproved
// target within the request deadlines. A nonzero code rejects the request.
func (s *ProbeServer) readCommand(w http.ResponseWriter, r *http.Request) (*agentv1.ConnectivityProbeCommand, int) {
	controller := http.NewResponseController(w)
	if controller.SetReadDeadline(time.Now().Add(3*time.Second)) != nil || controller.SetWriteDeadline(time.Now().Add(5*time.Second)) != nil {
		return nil, http.StatusServiceUnavailable
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16384))
	if err != nil {
		return nil, http.StatusBadRequest
	}
	command := new(agentv1.ConnectivityProbeCommand)
	if proto.Unmarshal(data, command) != nil || protodata.ValidateClosed(command.ProtoReflect()) != nil || s.rules.Validate(command) != nil || !proto.Equal(command.GetTarget(), s.targets[command.GetTarget().GetId()]) || command.GetPacket().GetTargetId() != command.GetTarget().GetId() {
		return nil, http.StatusForbidden
	}
	return command, 0
}

// operate applies one probe operation to the device's slot id, whose existing
// job (if any) matches command. It runs under s.mu; a nonzero code rejects.
func (s *ProbeServer) operate(ctx context.Context, id string, job *probeJob, command *agentv1.ConnectivityProbeCommand) (*agentv1.ConnectivityProbeResponse, int) {
	response := &agentv1.ConnectivityProbeResponse{}
	switch command.GetOperation() {
	case agentv1.ConnectivityProbeOperation_CONNECTIVITY_PROBE_OPERATION_PREPARE:
		receipt, code := s.prepareReceiver(ctx, id, job, command)
		if code != 0 {
			return nil, code
		}
		response.Ready = true
		response.ReceiptEnvelope = receipt
	case agentv1.ConnectivityProbeOperation_CONNECTIVITY_PROBE_OPERATION_TRANSMIT:
		receipt, code := s.transmit(ctx, id, job, command)
		if code != 0 {
			return nil, code
		}
		response.Ready = true
		response.ReceiptEnvelope = receipt
	case agentv1.ConnectivityProbeOperation_CONNECTIVITY_PROBE_OPERATION_OBSERVE:
		if command.GetTarget().GetReceiver().GetOrigin() != s.origin || job == nil || job.receiver == nil {
			return nil, http.StatusConflict
		}
		if len(job.receipt) == 0 {
			digest, err := job.receiver.observe()
			if err != nil {
				return nil, http.StatusUnprocessableEntity
			}
			if len(digest) != 0 {
				job.receipt, err = s.authority.Sign(ctx, &agentv1.ConnectivityProbeReceipt{Packet: command.GetPacket(), Target: command.GetTarget(), Received: true, TransportSha256: digest}, s.key)
				if err != nil {
					return nil, http.StatusInternalServerError
				}
			}
		}
		response.Ready = true
		response.ReceiptEnvelope = job.receipt
	case agentv1.ConnectivityProbeOperation_CONNECTIVITY_PROBE_OPERATION_RELEASE:
		if job != nil {
			delete(s.jobs, id)
			if job.receiver != nil {
				if err := job.receiver.close(); err != nil {
					return nil, http.StatusInternalServerError
				}
			}
		}
		response.Ready = true
	default:
		return nil, http.StatusBadRequest
	}
	return response, 0
}

// prepareReceiver starts, at most once per slot, a bounded packet receiver for
// a target this witness receives and returns its signed readiness receipt.
func (s *ProbeServer) prepareReceiver(ctx context.Context, id string, job *probeJob, command *agentv1.ConnectivityProbeCommand) ([]byte, int) {
	if command.GetTarget().GetReceiver().GetOrigin() != s.origin {
		return nil, http.StatusForbidden
	}
	if job == nil {
		if len(s.jobs) >= 32 {
			return nil, http.StatusTooManyRequests
		}
		receiver, err := receivePackets(command.GetTarget(), command.GetPacket().GetNonce())
		if err != nil {
			return nil, http.StatusUnprocessableEntity
		}
		job = &probeJob{command: proto.CloneOf(command), receiver: receiver, expires: time.Now().Add(10 * time.Second)}
		s.jobs[id] = job
		digest := sha256.Sum256(receiver.expected)
		job.readyReceipt, err = s.authority.Sign(ctx, &agentv1.ConnectivityProbeReceipt{Packet: command.GetPacket(), Target: command.GetTarget(), ReceiverReady: true, TransportSha256: digest[:]}, s.key)
		if err != nil {
			return nil, http.StatusInternalServerError
		}
	}
	if len(job.readyReceipt) == 0 {
		return nil, http.StatusConflict
	}
	return job.readyReceipt, 0
}

// transmit sends, at most once per slot, the probe packet for a target this
// witness sends from and returns its signed transmission receipt.
func (s *ProbeServer) transmit(ctx context.Context, id string, job *probeJob, command *agentv1.ConnectivityProbeCommand) ([]byte, int) {
	if command.GetTarget().GetSender().GetOrigin() != s.origin {
		return nil, http.StatusForbidden
	}
	if job == nil {
		if len(s.jobs) >= 32 {
			return nil, http.StatusTooManyRequests
		}
		job = &probeJob{command: proto.CloneOf(command), expires: time.Now().Add(10 * time.Second)}
		s.jobs[id] = job
		digest, err := transmitPacket(ctx, command.GetTarget(), command.GetPacket().GetNonce())
		if err != nil {
			return nil, http.StatusUnprocessableEntity
		}
		receipt := &agentv1.ConnectivityProbeReceipt{Packet: command.GetPacket(), Target: command.GetTarget(), Transmitted: true, TransportSha256: digest}
		job.receipt, err = s.authority.Sign(ctx, receipt, s.key)
		if err != nil {
			return nil, http.StatusInternalServerError
		}
	}
	if len(job.receipt) == 0 {
		return nil, http.StatusConflict
	}
	return job.receipt, 0
}
