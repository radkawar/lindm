// SPDX-License-Identifier: Apache-2.0

package integrations

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/google/uuid"

	integrationsv1 "lindm/gen/lindm/integrations/v1"
	"lindm/internal/integrations/integrationdb"
)

// One cache slot per bounded worker reuses TLS pools without an unbounded
// destination cache. It never retains plaintext signing material.
type deliverySender struct {
	service   *Service
	targetID  uuid.UUID
	version   int64
	client    *http.Client
	transport *http.Transport
	tlsConfig *tls.Config
	address   string
}

func (sender *deliverySender) close() {
	if sender.transport != nil {
		sender.transport.CloseIdleConnections()
	}
}
func (sender *deliverySender) configure(target integrationdb.IntegrationDestination) error {
	if sender.targetID == target.ID && sender.version == target.Version {
		return nil
	}
	endpoint, err := url.Parse(target.Endpoint)
	if err != nil {
		return err
	}
	var roots *x509.CertPool
	if target.PinnedCaPem != "" {
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(target.PinnedCaPem)) {
			return errors.New("invalid trust roots")
		}
	}
	if target.Kind == int32(integrationsv1.DestinationKind_DESTINATION_KIND_SYSLOG_TLS) && roots == nil {
		return errors.New("syslog requires pinned roots")
	}
	sender.close()
	sender.tlsConfig = &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: endpoint.Hostname()}
	sender.address = endpoint.Host
	sender.transport = &http.Transport{TLSClientConfig: sender.tlsConfig, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, MaxResponseHeaderBytes: 16 << 10, MaxIdleConns: 1, MaxIdleConnsPerHost: 1, MaxConnsPerHost: 1, IdleConnTimeout: 30 * time.Second}
	sender.client = &http.Client{Transport: sender.transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	sender.targetID = target.ID
	sender.version = target.Version
	return nil
}
func (sender *deliverySender) send(ctx context.Context, target integrationdb.IntegrationDestination, event integrationdb.IntegrationEvent, delivery integrationdb.IntegrationDelivery) string {
	if err := sender.configure(target); err != nil {
		return "invalid_destination_trust"
	}
	switch integrationsv1.DestinationKind(target.Kind) {
	case integrationsv1.DestinationKind_DESTINATION_KIND_WEBHOOK:
		return sender.webhook(ctx, target, event, delivery)
	case integrationsv1.DestinationKind_DESTINATION_KIND_SYSLOG_TLS:
		if err := sender.syslog(ctx, event, delivery); err != nil {
			return "syslog_transport_failed"
		}
		return ""
	default:
		return "invalid_destination_kind"
	}
}
func signature(secret []byte, stamp string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(stamp))
	mac.Write([]byte{'.'})
	mac.Write(body)
	return "v1=" + hex.EncodeToString(mac.Sum(nil))
}
func (sender *deliverySender) webhook(ctx context.Context, target integrationdb.IntegrationDestination, event integrationdb.IntegrationEvent, delivery integrationdb.IntegrationDelivery) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.Endpoint, bytes.NewReader(event.Payload))
	if err != nil {
		return "invalid_destination_endpoint"
	}
	secret, err := sender.service.aead.Open(nil, nil, target.SecretCiphertext, target.ID[:])
	if err != nil {
		return "destination_secret_unreadable"
	}
	defer clear(secret)
	stamp := strconv.FormatInt(sender.service.clock().Unix(), 10)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Lindm-Timestamp", stamp)
	req.Header.Set("Lindm-Event-ID", event.ID.String())
	req.Header.Set("Lindm-Delivery-ID", delivery.ID.String())
	req.Header.Set("Lindm-Replay-Count", strconv.FormatInt(int64(delivery.ReplayCount), 10))
	req.Header.Set("Lindm-Signature", signature(secret, stamp, event.Payload))
	if target.PreviousSecretExpiresAt.Valid && sender.service.clock().Before(target.PreviousSecretExpiresAt.Time) {
		previous, openErr := sender.service.aead.Open(nil, nil, target.PreviousSecretCiphertext, target.ID[:])
		if openErr != nil {
			return "destination_secret_unreadable"
		}
		req.Header.Set("Lindm-Signature-Previous", signature(previous, stamp, event.Payload))
		clear(previous)
	}
	response, err := sender.client.Do(req)
	if err != nil {
		return "webhook_transport_failed"
	}
	// Bodies are never retained, returned or logged. A bounded drain permits reuse
	// without allowing a hostile receiver to consume unbounded memory or work.
	_, drainErr := io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	closeErr := response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "webhook_http_" + strconv.Itoa(response.StatusCode)
	}
	if drainErr != nil || closeErr != nil {
		return "webhook_response_failed"
	}
	return ""
}
func (sender *deliverySender) syslog(ctx context.Context, event integrationdb.IntegrationEvent, delivery integrationdb.IntegrationDelivery) (result error) {
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: sender.tlsConfig}
	conn, err := dialer.DialContext(ctx, "tcp", sender.address)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, conn.Close()) }()
	deadline := time.Now().Add(15 * time.Second)
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	if err = conn.SetDeadline(deadline); err != nil {
		return err
	}
	// RFC5424 MSG is UTF-8 JSON; the BOM explicitly declares UTF-8. Structured
	// data is NILVALUE; stable event/delivery IDs and replay count live in MSG.
	message := fmt.Sprintf("<134>1 %s lindmd lindm - audit - \xef\xbb\xbf{\"delivery_id\":%q,\"replay_count\":%d,\"event\":%s}", event.OccurredAt.Time.UTC().Format(time.RFC3339Nano), delivery.ID.String(), delivery.ReplayCount, event.Payload)
	// RFC6587 octet counting (not newline-delimited); TLS is mandatory.
	_, err = fmt.Fprintf(conn, "%d %s", len(message), message)
	return err
}
