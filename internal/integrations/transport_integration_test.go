// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integrations

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	"lindm/internal/integrations/integrationdb"
)

func TestHTTPSWebhookIndependentHMACRotationRetry(t *testing.T) {
	f := newIntegrationFixture(t)
	current, previous := bytes.Repeat([]byte{0x42}, 32), bytes.Repeat([]byte{0x24}, 32)
	type observation struct {
		body                    []byte
		event, delivery, replay string
	}
	observed := make(chan observation, 3)
	var calls atomic.Int32
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 16385))
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		if len(body) > 16384 {
			t.Error("oversized event")
		}
		stamp := r.Header.Get("Lindm-Timestamp")
		seconds, err := strconv.ParseInt(stamp, 10, 64)
		if err != nil || time.Since(time.Unix(seconds, 0)) > time.Minute {
			t.Error("missing/replayed timestamp")
		}
		verify := func(key []byte, header string) {
			got, decodeErr := hex.DecodeString(strings.TrimPrefix(r.Header.Get(header), "v1="))
			if decodeErr != nil {
				t.Error(decodeErr)
				return
			}
			input := append([]byte(stamp+"."), body...)
			mac := hmac.New(sha256.New, key)
			if _, writeErr := mac.Write(input); writeErr != nil {
				t.Error(writeErr)
				return
			}
			if !hmac.Equal(mac.Sum(nil), got) {
				t.Errorf("independent HMAC rejected %s", header)
			}
		}
		verify(current, "Lindm-Signature")
		verify(previous, "Lindm-Signature-Previous")
		observed <- observation{body: body, event: r.Header.Get("Lindm-Event-ID"), delivery: r.Header.Get("Lindm-Delivery-ID"), replay: r.Header.Get("Lindm-Replay-Count")}
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			if _, err = io.WriteString(w, "receiver-private-secret"); err != nil {
				t.Error(err)
			}
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(receiver.Close)
	roots := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: receiver.Certificate().Raw}))
	target := f.target(t, 1, receiver.URL, roots, previous)
	_, err := integrationdb.New(f.pool).RotateDestinationSecret(f.ctx, integrationdb.RotateDestinationSecretParams{ID: target.ID, Ciphertext: f.service.aead.Seal(nil, nil, current, target.ID[:]), ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}})
	requireNoError(t, err)
	eventID := f.event(t, "device-network")
	sender := &deliverySender{service: f.service}
	t.Cleanup(sender.close)
	worked, err := f.service.workOne(f.ctx, sender)
	requireNoError(t, err)
	if !worked {
		t.Fatal("worker found no event")
	}
	var one observation
	select {
	case one = <-observed:
	case <-f.ctx.Done():
		t.Fatal("first HTTPS delivery deadline")
	}
	var status int32
	var reason string
	requireNoError(t, f.conn.QueryRow(f.ctx, "SELECT status,last_error FROM integration_deliveries WHERE event_id=$1", eventID).Scan(&status, &reason))
	if status != 1 || reason != "webhook_http_503" {
		t.Fatalf("HTTP failure not retained as bounded retry: %d %q", status, reason)
	}
	_, err = f.conn.Exec(f.ctx, "UPDATE integration_deliveries SET next_attempt_at=clock_timestamp() WHERE event_id=$1", eventID)
	requireNoError(t, err)
	worked, err = f.service.workOne(f.ctx, sender)
	requireNoError(t, err)
	if !worked {
		t.Fatal("retry not claimed")
	}
	var two observation
	select {
	case two = <-observed:
	case <-f.ctx.Done():
		t.Fatal("retry HTTPS delivery deadline")
	}
	if one.event != eventID.String() || one.event != two.event || one.delivery == "" || one.delivery != two.delivery || one.replay != "0" || !bytes.Equal(one.body, two.body) {
		t.Fatal("retry identity/body not stable")
	}
	if bytes.Contains(two.body, []byte("super-secret")) {
		t.Fatal("audit reason leaked to receiver")
	}
	requireNoError(t, f.conn.QueryRow(f.ctx, "SELECT status FROM integration_deliveries WHERE event_id=$1", eventID).Scan(&status))
	if status != 3 {
		t.Fatal("successful webhook not acknowledged")
	}
}

func TestSyslogTLSOctetCountIndependentReceiver(t *testing.T) {
	f := newIntegrationFixture(t)
	certSource := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := certSource.TLS.Certificates[0]
	roots := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certSource.Certificate().Raw}))
	certSource.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}})
	requireNoError(t, err)
	t.Cleanup(func() {
		if err := listener.Close(); err != nil {
			t.Error(err)
		}
	})
	type received struct {
		message []byte
		err     error
	}
	result := make(chan received, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			result <- received{err: acceptErr}
			return
		}
		deadlineErr := conn.SetDeadline(time.Now().Add(10 * time.Second))
		if deadlineErr != nil {
			closeErr := conn.Close()
			result <- received{err: fmt.Errorf("deadline %v; close %v", deadlineErr, closeErr)}
			return
		}
		reader := bufio.NewReader(conn)
		prefix, readErr := reader.ReadString(' ')
		if readErr != nil {
			closeErr := conn.Close()
			result <- received{err: fmt.Errorf("prefix %v; close %v", readErr, closeErr)}
			return
		}
		count, parseErr := strconv.Atoi(strings.TrimSuffix(prefix, " "))
		if parseErr != nil || count < 1 || count > 32768 {
			closeErr := conn.Close()
			result <- received{err: fmt.Errorf("invalid frame count %d: %v; close %v", count, parseErr, closeErr)}
			return
		}
		message := make([]byte, count)
		_, readErr = io.ReadFull(reader, message)
		closeErr := conn.Close()
		if readErr == nil {
			readErr = closeErr
		}
		result <- received{message, readErr}
	}()
	f.target(t, 2, "tls://"+listener.Addr().String(), roots, nil)
	event := f.event(t, "syslog-device")
	sender := &deliverySender{service: f.service}
	t.Cleanup(sender.close)
	worked, err := f.service.workOne(f.ctx, sender)
	requireNoError(t, err)
	if !worked {
		t.Fatal("syslog work not claimed")
	}
	select {
	case received := <-result:
		requireNoError(t, received.err)
		if !bytes.HasPrefix(received.message, []byte("<134>1 ")) || !bytes.Contains(received.message, []byte(" lindmd lindm - audit - \xef\xbb\xbf")) || !bytes.Contains(received.message, []byte(event.String())) || !bytes.Contains(received.message, []byte(`"delivery_id"`)) {
			t.Fatalf("invalid RFC5424 frame: %q", received.message)
		}
		if bytes.Contains(received.message, []byte("super-secret")) {
			t.Fatal("syslog leaked reason")
		}
	case <-f.ctx.Done():
		t.Fatal("TLS receiver deadline")
	}
}

func TestHTTPSRejectsUnpinnedReceiverAndRedirect(t *testing.T) {
	f := newIntegrationFixture(t)
	var redirected atomic.Int32
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1); w.WriteHeader(204) }))
	t.Cleanup(other.Close)
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(receiver.Close)
	target := f.target(t, 1, receiver.URL, "", bytes.Repeat([]byte{8}, 32))
	event := f.event(t, "tls-test")
	sender := &deliverySender{service: f.service}
	t.Cleanup(sender.close)
	_, err := f.service.workOne(f.ctx, sender)
	requireNoError(t, err)
	var reason string
	requireNoError(t, f.conn.QueryRow(f.ctx, "SELECT last_error FROM integration_deliveries WHERE event_id=$1", event).Scan(&reason))
	if reason != "webhook_transport_failed" {
		t.Fatalf("untrusted TLS accepted: %s", reason)
	}
	roots := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: receiver.Certificate().Raw}))
	_, err = f.conn.Exec(f.ctx, "UPDATE integration_destinations SET pinned_ca_pem=$2,version=version+1 WHERE id=$1", target.ID, roots)
	requireNoError(t, err)
	_, err = f.conn.Exec(f.ctx, "UPDATE integration_deliveries SET next_attempt_at=clock_timestamp() WHERE event_id=$1", event)
	requireNoError(t, err)
	_, err = f.service.workOne(f.ctx, sender)
	requireNoError(t, err)
	requireNoError(t, f.conn.QueryRow(f.ctx, "SELECT last_error FROM integration_deliveries WHERE event_id=$1", event).Scan(&reason))
	if reason != "webhook_http_307" || redirected.Load() != 0 {
		t.Fatal("webhook followed redirect or lost failure")
	}
}
