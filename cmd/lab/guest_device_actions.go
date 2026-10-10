//go:build linux

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"

	agentv1 "lindm/gen/lindm/agent/v1"
	devicev1 "lindm/gen/lindm/device/v1"
	"lindm/gen/lindm/device/v1/devicev1connect"
	"lindm/internal/agent/config"
	"lindm/internal/agent/localrpc"
)

// guestActionAuthorizationDenied is an unprivileged negative-qualification client.
// It consumes real server intent and root challenge, but NEVER calls Start. Even
// an erroneously granted negative test cannot cause a native destructive effect.
func guestActionAuthorizationDenied(ctx context.Context, output io.Writer) error {
	return guestDeviceActionProbe(ctx, output, true)
}

// guestLiveEraseWithoutReport obtains and consumes genuine online authority,
// then intentionally omits result attestation/delivery. The host cuts this VM's
// network after the durable Start reply and observes independent forced poweroff.
func guestLiveEraseWithoutReport(ctx context.Context, output io.Writer) error {
	return guestDeviceActionProbe(ctx, output, false)
}

func guestDeviceActionProbe(ctx context.Context, output io.Writer, denialExpected bool) (err error) {
	document, err := config.Load(config.NetworkConfigPath)
	if err != nil {
		return err
	}
	if uint32(os.Geteuid()) != document.NetworkUID {
		return errors.New("action authorization probe requires configured network UID")
	}
	data, err := io.ReadAll(io.LimitReader(os.Stdin, 4097))
	if err != nil || len(data) > 4096 {
		return errors.New("bounded action probe input required")
	}
	input := new(agentv1.GetDeviceActionRequest)
	if err := protojson.Unmarshal(data, input); err != nil {
		return err
	}
	if err := protovalidate.Validate(input); err != nil {
		return err
	}
	executor, cleanup, err := localrpc.Dial(document.SocketPath)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, cleanup()) }()
	connected, err := executor.GetConnection(ctx, connect.NewRequest(&agentv1.GetConnectionRequest{}))
	if err != nil {
		return guestRPCFailure("get action probe connection", err)
	}
	connection := connected.Msg
	if err := guestConnection(connection); err != nil {
		return err
	}
	if !connection.GetSessionEpochUsable() || connection.GetSessionEpoch() == 0 {
		return errors.New("action probe requires existing committed management session")
	}
	origin, err := url.Parse(connection.GetDeviceOrigin())
	if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") {
		return errors.New("invalid protected device origin")
	}
	leaf, err := guestCertificate(connection.GetCertificatePem(), connection.GetDeploymentId(), connection.GetDeviceId(), connection.GetEnrollmentGeneration())
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(connection.GetTransportCaPem()) {
		return errors.New("invalid protected transport pins")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, GetClientCertificate: func(handshake *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		signer, err := localrpc.NewTLSSigner(handshake.Context(), executor, leaf)
		if err != nil {
			return nil, err
		}
		return &tls.Certificate{Certificate: [][]byte{leaf.Raw}, Leaf: leaf, PrivateKey: signer}, nil
	}}, DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext, ForceAttemptHTTP2: true, MaxConnsPerHost: 2, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second}
	defer transport.CloseIdleConnections()
	client := devicev1connect.NewDeviceServiceClient(&http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, connection.GetDeviceOrigin(), connect.WithReadMaxBytes(1<<20))
	work, err := client.GetDeviceActionWork(ctx, connect.NewRequest(&devicev1.GetDeviceActionWorkRequest{SessionEpoch: connection.GetSessionEpoch()}))
	if err != nil {
		return guestRPCFailure("get negative action intent", err)
	}
	if work.Msg.GetWork().GetActionId() != input.GetActionId() {
		return errors.New("server work does not match exact negative action")
	}
	prepared, err := executor.PrepareDeviceAction(ctx, connect.NewRequest(&agentv1.PrepareDeviceActionRequest{IntentEnvelope: work.Msg.GetWork().GetIntentEnvelope()}))
	if err != nil {
		return guestRPCFailure("prepare negative action challenge", err)
	}
	if prepared.Msg.GetStatus().GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_PREPARED || len(prepared.Msg.GetChallengeProof()) == 0 {
		return errors.New("negative action lacks a fresh root challenge")
	}
	grant, rejected := client.AuthorizeDeviceActionStart(ctx, connect.NewRequest(&devicev1.AuthorizeDeviceActionStartRequest{SessionEpoch: connection.GetSessionEpoch(), ActionId: input.GetActionId(), ChallengeProof: prepared.Msg.GetChallengeProof()}))
	if !denialExpected {
		if rejected != nil {
			return guestRPCFailure("authorize live erase fault scenario", rejected)
		}
		if prepared.Msg.GetNativePlan().GetSpec().GetCryptoErase().GetMode() != agentv1.CryptoEraseMode_CRYPTO_ERASE_MODE_LIVE_ROOT_HEADER {
			return errors.New("report-loss probe admits only explicitly approved live-root erase")
		}
		started, err := executor.StartDeviceAction(ctx, connect.NewRequest(&agentv1.StartDeviceActionRequest{ActionId: input.GetActionId(), StartGrantEnvelope: grant.Msg.GetStartGrantEnvelope()}))
		if err != nil {
			return guestRPCFailure("consume live erase start authority", err)
		}
		return writeGuestEvidence(output, started.Msg)
	}
	var denial *connect.Error
	if !errors.As(rejected, &denial) || denial.Code() != connect.CodePermissionDenied || denial.Meta().Get("Lindm-Reason") == "" {
		return errors.New("server did not explicitly deny negative destructive start authority")
	}
	status, err := executor.GetDeviceAction(ctx, connect.NewRequest(input))
	if err != nil {
		return err
	}
	if status.Msg.GetStatus().GetState() != agentv1.DeviceActionState_DEVICE_ACTION_STATE_PREPARED || status.Msg.GetStatus().GetStartedAt() != nil {
		return errors.New("negative approval started a native action")
	}
	return json.NewEncoder(output).Encode(struct {
		Code       string    `json:"code"`
		Reason     string    `json:"reason"`
		ObservedAt time.Time `json:"observed_at"`
	}{denial.Code().String(), denial.Meta().Get("Lindm-Reason"), time.Now().UTC()})
}
