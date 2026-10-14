// SPDX-License-Identifier: Apache-2.0

//go:build linux

package connectivityguard

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/trust"
)

func (g *Guard) probe(ctx context.Context, action string, applied *agentv1.ResourceOwnershipSnapshot) ([]*agentv1.ConnectivityProbeEvidence, error) {
	result := make([]*agentv1.ConnectivityProbeEvidence, 0, len(g.config.Policy.GetProbes()))
	for _, target := range g.config.Policy.GetProbes() {
		evidence, err := g.probeOne(ctx, action, target, applied)
		if err != nil {
			return nil, err
		}
		result = append(result, evidence)
	}
	return result, nil
}
func (g *Guard) probeOne(ctx context.Context, action string, target *agentv1.ConnectivityProbeTarget, applied *agentv1.ResourceOwnershipSnapshot) (result *agentv1.ConnectivityProbeEvidence, err error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	packet := &agentv1.ConnectivityProbePacket{TargetId: target.GetId(), ActionId: action, Nonce: nonce}
	trace, err := startTrace(ctx, target, nonce, applied.GetFirewall())
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, trace.close()) }()
	var local *packetReceiver
	allow := target.GetExpected() == agentv1.ConnectivityProbeVerdict_CONNECTIVITY_PROBE_VERDICT_ALLOW
	var readyReceipt []byte
	if target.GetReceiver() != nil {
		reply, err := g.peerExchange(ctx, target.GetReceiver(), target, packet, agentv1.ConnectivityProbeOperation_CONNECTIVITY_PROBE_OPERATION_PREPARE)
		if err != nil {
			return nil, err
		}
		if err := VerifyProbeReadiness(ctx, g.authority, reply.GetReceiptEnvelope(), target.GetReceiver(), target, packet); err != nil {
			return nil, err
		}
		readyReceipt = reply.GetReceiptEnvelope()
	}
	if allow && target.GetDirection() == agentv1.ConnectivityProbeDirection_CONNECTIVITY_PROBE_DIRECTION_INPUT {
		local, err = receivePackets(target, nonce)
		if err != nil {
			return nil, err
		}
		defer func() { err = errors.Join(err, local.close()) }()
	}
	// Release is best-effort only for remote bounded read-only socket custody.
	// Regardless of reachability, the peer reaps every job within ten seconds.
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		for _, peer := range []*agentv1.ConnectivityProbePeer{target.GetSender(), target.GetReceiver()} {
			if peer != nil {
				_, _ = g.peerExchange(cleanup, peer, target, packet, agentv1.ConnectivityProbeOperation_CONNECTIVITY_PROBE_OPERATION_RELEASE)
			}
		}
	}()
	var sender []byte
	if target.GetDirection() == agentv1.ConnectivityProbeDirection_CONNECTIVITY_PROBE_DIRECTION_OUTPUT {
		_, sendErr := transmitPacket(ctx, target, nonce)
		if sendErr != nil && (allow || (!errors.Is(sendErr, unix.EPERM) && !errors.Is(sendErr, unix.EACCES))) {
			return nil, sendErr
		}
	} else {
		reply, err := g.peerExchange(ctx, target.GetSender(), target, packet, agentv1.ConnectivityProbeOperation_CONNECTIVITY_PROBE_OPERATION_TRANSMIT)
		if err != nil {
			return nil, err
		}
		if err := VerifyProbeReceipt(ctx, g.authority, reply.GetReceiptEnvelope(), target.GetSender(), target, packet, true); err != nil {
			return nil, err
		}
		sender = reply.GetReceiptEnvelope()
	}
	evidence, err := trace.observe(ctx)
	if err != nil {
		return nil, err
	}
	evidence.Nonce = nonce
	evidence.SenderReceipt = sender
	evidence.ReceiverReadyReceipt = readyReceipt
	if allow {
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			if local != nil {
				digest, err := local.observe()
				if err != nil {
					return nil, err
				}
				if len(digest) != 0 {
					break
				}
			} else {
				reply, err := g.peerExchange(ctx, target.GetReceiver(), target, packet, agentv1.ConnectivityProbeOperation_CONNECTIVITY_PROBE_OPERATION_OBSERVE)
				if err != nil {
					return nil, err
				}
				if len(reply.GetReceiptEnvelope()) != 0 {
					if err := VerifyProbeReceipt(ctx, g.authority, reply.GetReceiptEnvelope(), target.GetReceiver(), target, packet, false); err != nil {
						return nil, err
					}
					evidence.ReceiverReceipt = reply.GetReceiptEnvelope()
					break
				}
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-ticker.C:
			}
		}
	}
	return evidence, nil
}

// VerifyProbeReceipt is shared by root and server; no trusted plaintext packet
// witness exists. Exact target, action, nonce, direction and transport bytes bind
// every signed external send/receive receipt.
func VerifyProbeReceipt(ctx context.Context, authority *trust.Authority, envelope []byte, peer *agentv1.ConnectivityProbePeer, target *agentv1.ConnectivityProbeTarget, packet *agentv1.ConnectivityProbePacket, transmitted bool) error {
	receipt, err := verifyProbeBinding(ctx, authority, envelope, peer, target, packet)
	if err != nil {
		return err
	}
	if receipt.GetReceiverReady() || receipt.GetTransmitted() != transmitted || receipt.GetReceived() == transmitted {
		return ErrUnconfirmed
	}
	return nil
}

// VerifyProbeReadiness authenticates a live external receiver reservation. It
// deliberately cannot be used where an actual sent/received verdict is required.
func VerifyProbeReadiness(ctx context.Context, authority *trust.Authority, envelope []byte, peer *agentv1.ConnectivityProbePeer, target *agentv1.ConnectivityProbeTarget, packet *agentv1.ConnectivityProbePacket) error {
	receipt, err := verifyProbeBinding(ctx, authority, envelope, peer, target, packet)
	if err != nil {
		return err
	}
	if !receipt.GetReceiverReady() || receipt.GetTransmitted() || receipt.GetReceived() {
		return ErrUnconfirmed
	}
	return nil
}
func verifyProbeBinding(ctx context.Context, authority *trust.Authority, envelope []byte, peer *agentv1.ConnectivityProbePeer, target *agentv1.ConnectivityProbeTarget, packet *agentv1.ConnectivityProbePacket) (*agentv1.ConnectivityProbeReceipt, error) {
	receipt := new(agentv1.ConnectivityProbeReceipt)
	if peer == nil {
		return nil, ErrConflict
	}
	if err := authority.Verify(ctx, envelope, receipt, 1, ed25519.PublicKey(peer.GetPublicKey())); err != nil {
		return nil, err
	}
	transport, err := transportPacket(target, packet.GetNonce())
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(transport)
	if !proto.Equal(receipt.GetPacket(), packet) || !proto.Equal(receipt.GetTarget(), target) || !bytes.Equal(receipt.GetTransportSha256(), digest[:]) {
		return nil, ErrUnconfirmed
	}
	return receipt, nil
}
func (g *Guard) peerExchange(ctx context.Context, peer *agentv1.ConnectivityProbePeer, target *agentv1.ConnectivityProbeTarget, packet *agentv1.ConnectivityProbePacket, operation agentv1.ConnectivityProbeOperation) (*agentv1.ConnectivityProbeResponse, error) {
	origin, err := controllerAddress(peer.GetOrigin())
	if err != nil {
		return nil, err
	}
	config := g.config.TransportTLS.Clone()
	config.MinVersion = tls.VersionTLS13
	config.ServerName = origin.Hostname()
	config.ClientSessionCache = nil
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext, TLSClientConfig: config, TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 2 * time.Second, MaxResponseHeaderBytes: 4096, DisableKeepAlives: true, ForceAttemptHTTP2: false}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrConflict }}
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(&agentv1.ConnectivityProbeCommand{Target: target, Packet: packet, Operation: operation})
	if err != nil {
		return nil, err
	}
	origin.Path = ProbePath
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, origin.String(), bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/protobuf")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/protobuf" {
		return nil, ErrUnconfirmed
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 16385))
	if err != nil {
		return nil, err
	}
	if len(body) > 16384 {
		return nil, ErrUnconfirmed
	}
	reply := new(agentv1.ConnectivityProbeResponse)
	if err := proto.Unmarshal(body, reply); err != nil {
		return nil, err
	}
	if err := g.store.validate(reply); err != nil {
		return nil, err
	}
	if !reply.GetReady() {
		return nil, ErrUnconfirmed
	}
	return reply, nil
}
