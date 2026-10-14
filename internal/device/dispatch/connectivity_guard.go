// SPDX-License-Identifier: Apache-2.0

package dispatch

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/netip"

	"lindm/internal/device/core"

	"buf.build/go/protovalidate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/agent/connectivityguard"
	"lindm/internal/device/devicedb"
	"lindm/internal/protodata"
)

// ConnectivityConfirmationPath is mounted only on the authenticated device TLS
// mux. This bounded HTTP/protobuf RPC deliberately uses the actual connection's
// TLS exporter; a Connect request wrapper or transport-provided header is not
// accepted as proof of a new management connection.
const ConnectivityConfirmationPath = "/lindm.device.v1.ConnectivityGuard/Confirm"

// ConnectivityConfirmationHandler constructs a closed, pinned target policy.
// Targets are server/root provisioning, never supplied by a profile or caller.
// Reuse the existing StartKey DSSE signer and certificate/session DB fences.
func (s *Service) ConnectivityConfirmationHandler(approved []*agentv1.ConnectivityProbeTarget) (http.Handler, error) {
	rules, err := protovalidate.New(protovalidate.WithMessages(&agentv1.ConnectivityConfirmation{}, &agentv1.ConnectivityProbeTarget{}))
	if err != nil {
		return nil, err
	}
	targets := make(map[string]*agentv1.ConnectivityProbeTarget, len(approved))
	for _, target := range approved {
		if err := rules.Validate(target); err != nil {
			return nil, err
		}
		if err := protodata.ValidateClosed(target.ProtoReflect()); err != nil {
			return nil, err
		}
		if _, exists := targets[target.GetId()]; exists {
			return nil, core.ErrInternalState
		}
		targets[target.GetId()] = proto.CloneOf(target)
	}
	if len(targets) < 4 || len(targets) > 32 {
		return nil, core.ErrInternalState
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.confirmConnectivity(w, r, rules, targets)
	}), nil
}

func (s *Service) confirmConnectivity(w http.ResponseWriter, r *http.Request, rules protovalidate.Validator, targets map[string]*agentv1.ConnectivityProbeTarget) {
	w.Header().Set("Cache-Control", "no-store")
	reject := func(status int) { http.Error(w, "connectivity_confirmation_rejected", status) }
	if r.Method != http.MethodPost || r.URL.Path != ConnectivityConfirmationPath || r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/protobuf" {
		reject(http.StatusBadRequest)
		return
	}
	ctx, cancel := core.Bound(r.Context())
	defer cancel()
	if r.TLS == nil || r.TLS.DidResume || !r.TLS.HandshakeComplete {
		reject(http.StatusUnauthorized)
		return
	}
	leaf, deviceID, generationID, err := s.PresentedIdentity(r, s.Now())
	if err != nil {
		reject(http.StatusUnauthorized)
		return
	}
	principal, err := s.BindCertificate(ctx, leaf, deviceID, generationID, s.Now())
	if err != nil {
		reject(http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 384<<10))
	if err != nil {
		reject(http.StatusBadRequest)
		return
	}
	message := new(agentv1.ConnectivityConfirmation)
	if proto.Unmarshal(body, message) != nil || protodata.ValidateClosed(message.ProtoReflect()) != nil || rules.Validate(message) != nil {
		reject(http.StatusBadRequest)
		return
	}
	if message.GetDeploymentId() != s.DeploymentID.String() || message.GetDeviceId() != principal.DeviceID.String() || message.GetEnrollmentGeneration() != principal.GenerationID.String() {
		reject(http.StatusForbidden)
		return
	}
	exporter, err := r.TLS.ExportKeyingMaterial("EXPORTER-lindm-connectivity-guard-v1", message.GetNonce(), 32)
	if err != nil || !bytes.Equal(exporter, message.GetTlsExporter()) {
		reject(http.StatusForbidden)
		return
	}
	if len(message.GetProbes()) != len(targets) {
		reject(http.StatusForbidden)
		return
	}
	seen := make(map[string]bool, len(targets))
	for _, evidence := range message.GetProbes() {
		target := evidence.GetTarget()
		if seen[target.GetId()] || !proto.Equal(target, targets[target.GetId()]) {
			reject(http.StatusForbidden)
			return
		}
		seen[target.GetId()] = true
		address, err := netip.ParseAddr(target.GetAddress())
		if err != nil || (address.Is4() != (evidence.GetAddressFamily() == 4)) {
			reject(http.StatusForbidden)
			return
		}
		packet := &agentv1.ConnectivityProbePacket{TargetId: target.GetId(), ActionId: message.GetActionId(), Nonce: evidence.GetNonce()}
		if target.GetSender() != nil && connectivityguard.VerifyProbeReceipt(ctx, s.Authority, evidence.GetSenderReceipt(), target.GetSender(), target, packet, true) != nil {
			reject(http.StatusForbidden)
			return
		}
		if target.GetReceiver() != nil && connectivityguard.VerifyProbeReadiness(ctx, s.Authority, evidence.GetReceiverReadyReceipt(), target.GetReceiver(), target, packet) != nil {
			reject(http.StatusForbidden)
			return
		}
		if target.GetExpected() == agentv1.ConnectivityProbeVerdict_CONNECTIVITY_PROBE_VERDICT_ALLOW && target.GetReceiver() != nil && connectivityguard.VerifyProbeReceipt(ctx, s.Authority, evidence.GetReceiverReceipt(), target.GetReceiver(), target, packet, false) != nil {
			reject(http.StatusForbidden)
			return
		}
	}
	s.signConnectivityConfirmation(ctx, w, principal, message)
}

func (s *Service) signConnectivityConfirmation(ctx context.Context, w http.ResponseWriter, principal core.DevicePrincipal, message *agentv1.ConnectivityConfirmation) {
	reject := func(status int) { http.Error(w, "connectivity_confirmation_rejected", status) }
	if s.Signing == nil {
		reject(http.StatusServiceUnavailable)
		return
	}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		reject(http.StatusServiceUnavailable)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := devicedb.New(tx)
	device, err := s.LockAuthority(ctx, q, principal)
	if err != nil || uint64(device.Generation.SessionEpoch) != message.GetSessionEpoch() {
		reject(http.StatusForbidden)
		return
	}
	id, err := uuid.Parse(message.GetActionId())
	if err != nil {
		reject(http.StatusBadRequest)
		return
	}
	action, err := q.LockResourceAction(ctx, id)
	if err != nil || action.DeviceID != principal.DeviceID || action.GenerationID != principal.GenerationID || action.ClosedAt.Valid || action.ClosedReason != "" || len(action.StartGrantEnvelope) == 0 {
		reject(http.StatusForbidden)
		return
	}
	intent := new(agentv1.ResourceExecutionIntent)
	if proto.Unmarshal(action.IntentDocument, intent) != nil || !proto.Equal(intent.GetDesired().GetRef(), message.GetRef()) {
		reject(http.StatusForbidden)
		return
	}
	receipt, err := s.Authority.Sign(ctx, message, s.Signing.StartKey)
	if err != nil {
		reject(http.StatusServiceUnavailable)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		reject(http.StatusServiceUnavailable)
		return
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(&agentv1.ConnectivityConfirmationResponse{ReceiptEnvelope: receipt})
	if err != nil {
		reject(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/protobuf")
	w.Header().Set("Connection", "close")
	_, _ = w.Write(encoded)
}
