// SPDX-License-Identifier: Apache-2.0

//go:build linux

package connectivityguard

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func controllerAddress(origin string) (*url.URL, error) {
	u, err := url.Parse(origin)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, ErrConflict
	}
	return u, nil
}
func (g *Guard) confirm(ctx context.Context, message *agentv1.ConnectivityConfirmation) ([]byte, error) {
	origin, err := controllerAddress(g.config.Origin)
	if err != nil {
		return nil, err
	}
	port := origin.Port()
	if port == "" {
		port = "443"
	}
	config := g.config.TransportTLS.Clone()
	config.MinVersion = tls.VersionTLS13
	config.ServerName = origin.Hostname()
	config.NextProtos = []string{"http/1.1"}
	config.ClientSessionCache = nil
	dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second}, Config: config}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(origin.Hostname(), port))
	if err != nil {
		return nil, err
	}
	defer func() { _ = connection.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := connection.SetDeadline(deadline); err != nil {
		return nil, err
	}
	tlsConn, ok := connection.(*tls.Conn)
	if !ok {
		return nil, ErrUnconfirmed
	}
	state := tlsConn.ConnectionState()
	if !state.HandshakeComplete || state.DidResume || len(state.VerifiedChains) == 0 {
		return nil, ErrUnconfirmed
	}
	exporter, err := state.ExportKeyingMaterial(ExporterLabel, message.GetNonce(), 32)
	if err != nil {
		return nil, err
	}
	message.TlsExporter = exporter
	if err := g.store.validate(message); err != nil {
		return nil, err
	}
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		return nil, err
	}
	origin.Path = ConfirmationPath
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, origin.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Close = true
	request.Header.Set("Content-Type", "application/protobuf")
	if err := request.Write(connection); err != nil {
		return nil, err
	}
	response, err := http.ReadResponse(bufio.NewReaderSize(io.LimitReader(connection, (512<<10)+(16<<10)+8), 4096), request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/protobuf" {
		return nil, ErrUnconfirmed
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (512<<10)+9))
	if err != nil {
		return nil, err
	}
	if len(data) > (512<<10)+8 {
		return nil, ErrUnconfirmed
	}
	reply := new(agentv1.ConnectivityConfirmationResponse)
	if err := proto.Unmarshal(data, reply); err != nil {
		return nil, err
	}
	if err := g.store.validate(reply); err != nil {
		return nil, err
	}
	confirmed := new(agentv1.ConnectivityConfirmation)
	if err := g.authority.Verify(ctx, reply.GetReceiptEnvelope(), confirmed, 1, ed25519.PublicKey(g.config.Policy.GetConfirmationPublicKey())); err != nil {
		return nil, err
	}
	if !proto.Equal(confirmed, message) {
		return nil, errors.New("connectivity_confirmation_binding_rejected")
	}
	return reply.GetReceiptEnvelope(), nil
}

func (g *Guard) validateRetainedConfirmation(ctx context.Context, record *agentv1.ConnectivityGuardRecord) error {
	confirmed := new(agentv1.ConnectivityConfirmation)
	if err := g.authority.Verify(ctx, record.GetConfirmationReceipt(), confirmed, 1, ed25519.PublicKey(g.config.Policy.GetConfirmationPublicKey())); err != nil {
		return err
	}
	request := record.GetRequest()
	generation := request.GetTarget().GetFirewall().GetPersistent().GetGeneration()
	if generation == "" {
		generation = request.GetActionId()
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(record.GetApplied())
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	if confirmed.GetDeploymentId() != g.config.DeploymentID || confirmed.GetDeviceId() != g.config.DeviceID || confirmed.GetEnrollmentGeneration() != g.config.EnrollmentGeneration || confirmed.GetSessionEpoch() != g.config.SessionEpoch || confirmed.GetActionId() != request.GetActionId() || confirmed.GetAppliedGeneration() != generation || !proto.Equal(confirmed.GetRef(), request.GetPlan().GetRef()) || !bytes.Equal(confirmed.GetAppliedSha256(), sum[:]) || !bytes.Equal(confirmed.GetNonce(), record.GetNonce()) {
		return ErrUnconfirmed
	}
	return nil
}
