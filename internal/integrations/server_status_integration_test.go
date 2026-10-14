// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integrations

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lindm/internal/server/serverdb"
)

// A real configured TLS destination receives degradation and recovery, while
// repeated observations stay quiet and six-hour reminders survive restarts.
func TestServerStatusConfiguredWebhookDelivery(t *testing.T) {
	f := newIntegrationFixture(t)
	secret := bytes.Repeat([]byte{0x35}, 32)
	observed := make(chan map[string]any, 4)
	receiver := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 16385))
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		mac := hmac.New(sha256.New, secret)
		if _, err := mac.Write(append([]byte(r.Header.Get("Lindm-Timestamp")+"."), body...)); err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		signature, err := hex.DecodeString(strings.TrimPrefix(r.Header.Get("Lindm-Signature"), "v1="))
		if err != nil || !hmac.Equal(signature, mac.Sum(nil)) {
			t.Error("status webhook signature rejected")
			w.WriteHeader(401)
			return
		}
		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		observed <- payload
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(receiver.Close)
	roots := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: receiver.Certificate().Raw}))
	f.target(t, 1, receiver.URL, roots, secret)
	q := serverdb.New(f.pool)
	input := serverdb.RecordServerStatusTransitionParams{Instance: "0123456789abcdef0123456789abcdef", Component: "backups", State: 2}
	count, err := q.RecordServerStatusTransition(f.ctx, input)
	requireNoError(t, err)
	if count != 0 {
		t.Fatal("initial confirmed check sent a false recovery notification")
	}
	input.State = 4
	count, err = q.RecordServerStatusTransition(f.ctx, input)
	requireNoError(t, err)
	if count != 1 {
		t.Fatal("degradation did not create one durable delivery")
	}
	count, err = q.RecordServerStatusTransition(f.ctx, input)
	requireNoError(t, err)
	if count != 0 {
		t.Fatal("repeated observation emitted an unbounded alert")
	}
	sender := &deliverySender{service: f.service}
	t.Cleanup(sender.close)
	worked, err := f.service.workOne(f.ctx, sender)
	requireNoError(t, err)
	if !worked {
		t.Fatal("configured destination had no status delivery")
	}
	select {
	case payload := <-observed:
		if payload["action"] != "server.status.failed" || payload["resource_id"] != "server/"+input.Instance+"/backups" {
			t.Fatalf("wrong status evidence: %v", payload)
		}
		for _, forbidden := range []string{"reason", "details", "database_url", "artifact", "secret"} {
			if _, ok := payload[forbidden]; ok {
				t.Fatalf("status alert leaked %s", forbidden)
			}
		}
	case <-f.ctx.Done():
		t.Fatal("status webhook delivery deadline")
	}
	_, err = f.conn.Exec(f.ctx, "UPDATE server_status_alerts SET notified_at = CURRENT_TIMESTAMP - interval '7 hours' WHERE instance=$1 AND component=$2", input.Instance, input.Component)
	requireNoError(t, err)
	count, err = q.RecordServerStatusTransition(f.ctx, input)
	requireNoError(t, err)
	if count != 1 {
		t.Fatal("persisted overdue alert did not emit its bounded reminder")
	}
	input.State = 2
	count, err = q.RecordServerStatusTransition(f.ctx, input)
	requireNoError(t, err)
	if count != 1 {
		t.Fatal("recovery did not emit")
	}
	for _, action := range []string{"server.status.failed", "server.status.recovered"} {
		worked, err = f.service.workOne(f.ctx, sender)
		requireNoError(t, err)
		if !worked {
			t.Fatal("status reminder or recovery not claimed")
		}
		select {
		case payload := <-observed:
			if payload["action"] != action {
				t.Fatalf("delivery ordering: %v, want %s", payload, action)
			}
		case <-f.ctx.Done():
			t.Fatal("status transition delivery deadline")
		}
	}
	// A newly imported notice must reach the configured receiver even when
	// the previous authenticated notice already had the same attention state.
	input.Component, input.State = "server_release_feed", 3
	input.EvidenceKey = strings.Repeat("a", 64)
	count, err = q.RecordServerStatusTransition(f.ctx, input)
	requireNoError(t, err)
	if count != 1 {
		t.Fatal("initial release notice did not emit")
	}
	count, err = q.RecordServerStatusTransition(f.ctx, input)
	requireNoError(t, err)
	if count != 0 {
		t.Fatal("unchanged release notice emitted an unbounded reminder")
	}
	input.EvidenceKey = strings.Repeat("b", 64)
	count, err = q.RecordServerStatusTransition(f.ctx, input)
	requireNoError(t, err)
	if count != 1 {
		t.Fatal("new release notice waited for the old reminder deadline")
	}
	for range 2 {
		worked, err = f.service.workOne(f.ctx, sender)
		requireNoError(t, err)
		if !worked {
			t.Fatal("release notice delivery was not claimed")
		}
		select {
		case payload := <-observed:
			if payload["action"] != "server.status.attention" || payload["resource_id"] != "server/"+input.Instance+"/server_release_feed" {
				t.Fatalf("wrong release alert: %v", payload)
			}
		case <-f.ctx.Done():
			t.Fatal("release notice delivery deadline")
		}
	}
}

func TestStatusWaitsForAnEnabledDestination(t *testing.T) {
	f := newIntegrationFixture(t)
	q := serverdb.New(f.pool)
	input := serverdb.RecordServerStatusTransitionParams{Instance: "0123456789abcdef0123456789abcdef", Component: "backups", State: 4}
	count, err := q.RecordServerStatusTransition(f.ctx, input)
	requireNoError(t, err)
	if count != 0 {
		t.Fatal("status reported delivery without an enabled destination")
	}
	var states int
	requireNoError(t, f.conn.QueryRow(f.ctx, "SELECT count(*) FROM server_status_alerts").Scan(&states))
	if states != 0 {
		t.Fatal("undeliverable degradation consumed its notification cadence")
	}
	f.target(t, 1, "https://receiver.example.test", "", bytes.Repeat([]byte{0x47}, 32))
	count, err = q.RecordServerStatusTransition(f.ctx, input)
	requireNoError(t, err)
	if count != 1 {
		t.Fatal("configuring a destination did not capture existing degradation")
	}
	tx, err := f.pool.Begin(f.ctx)
	requireNoError(t, err)
	input.State = 2
	count, err = serverdb.New(tx).RecordServerStatusTransition(f.ctx, input)
	requireNoError(t, err)
	if count != 1 {
		t.Fatal("transactional recovery did not stage its event")
	}
	requireNoError(t, tx.Rollback(f.ctx))
	count, err = q.RecordServerStatusTransition(f.ctx, input)
	requireNoError(t, err)
	if count != 1 {
		t.Fatal("rolled-back recovery consumed its durable alert state")
	}
}
