// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integrations

import (
	"bytes"
	"context"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	integrationsv1 "lindm/gen/lindm/integrations/v1"
	"lindm/internal/identity"
	"lindm/internal/integrations/integrationdb"
)

func TestDestinationMutationReceiptsEncryptionAndVersionFences(t *testing.T) {
	f := newIntegrationFixture(t)
	secret := bytes.Repeat([]byte("s"), 32)
	create := &integrationsv1.CreateDestinationRequest{RequestId: uuid.NewString(), Config: &integrationsv1.DestinationConfig{DisplayName: "Receiver", Kind: integrationsv1.DestinationKind_DESTINATION_KIND_WEBHOOK, Endpoint: "https://receiver.example/events", Enabled: true}, SigningSecret: secret, Reason: "enable integration"}
	first, err := f.service.CreateDestination(f.ctx, connect.NewRequest(create))
	requireNoError(t, err)
	retry, err := f.service.CreateDestination(f.ctx, connect.NewRequest(create))
	requireNoError(t, err)
	if !proto.Equal(first.Msg, retry.Msg) {
		t.Fatal("create retry changed receipt")
	}
	id, err := uuid.Parse(first.Msg.Destination.Id)
	requireNoError(t, err)
	stored, err := integrationdb.New(f.pool).LockDestination(f.ctx, id)
	requireNoError(t, err)
	if bytes.Contains(stored.SecretCiphertext, secret) || bytes.Equal(stored.SecretCiphertext, secret) {
		t.Fatal("plaintext stored")
	}
	decoded, err := f.service.aead.Open(nil, nil, stored.SecretCiphertext, id[:])
	requireNoError(t, err)
	if !bytes.Equal(decoded, secret) {
		t.Fatal("credential not decryptable")
	}
	clear(decoded)
	wrongID := uuid.New()
	if _, err = f.service.aead.Open(nil, nil, stored.SecretCiphertext, wrongID[:]); err == nil {
		t.Fatal("ciphertext not bound to destination")
	}
	receipt, err := integrationdb.New(f.pool).LockMutation(f.ctx, integrationdb.LockMutationParams{ActorID: f.actor.ID, RequestID: uuid.MustParse(create.RequestId)})
	requireNoError(t, err)
	if bytes.Contains(receipt.Response, secret) || bytes.Contains(receipt.RequestHash, secret) {
		t.Fatal("secret persisted in receipt")
	}
	update := &integrationsv1.UpdateDestinationRequest{RequestId: uuid.NewString(), DestinationId: id.String(), Config: proto.CloneOf(create.Config), ExpectedVersion: 1, Reason: "pause receiver"}
	update.Config.Enabled = false
	changed, err := f.service.UpdateDestination(f.ctx, connect.NewRequest(update))
	requireNoError(t, err)
	if changed.Msg.Destination.Version != 2 || changed.Msg.Destination.Config.Enabled {
		t.Fatal("disable/version transition invalid")
	}
	stale := proto.CloneOf(update)
	stale.RequestId = uuid.NewString()
	_, err = f.service.UpdateDestination(f.ctx, connect.NewRequest(stale))
	if connect.CodeOf(err) != connect.CodeAborted {
		t.Fatalf("stale update accepted: %v", err)
	}
	afterDisable := f.event(t, "disabled-destination")
	var count int
	requireNoError(t, f.conn.QueryRow(f.ctx, "SELECT count(*) FROM integration_deliveries WHERE event_id=$1", afterDisable).Scan(&count))
	if count != 0 {
		t.Fatal("disabled destination received new fanout")
	}
	rotation := &integrationsv1.RotateDestinationSecretRequest{RequestId: uuid.NewString(), DestinationId: id.String(), SigningSecret: bytes.Repeat([]byte("r"), 32), OverlapSeconds: 3600, ExpectedVersion: 2, Reason: "rotate receiver key"}
	rotated, err := f.service.RotateDestinationSecret(f.ctx, connect.NewRequest(rotation))
	requireNoError(t, err)
	if rotated.Msg.Destination.Version != 3 || rotated.Msg.Destination.PreviousSecretExpiresAt == nil {
		t.Fatal("rotation receipt incomplete")
	}
	overlap := proto.CloneOf(rotation)
	overlap.RequestId = uuid.NewString()
	overlap.ExpectedVersion = 3
	_, err = f.service.RotateDestinationSecret(f.ctx, connect.NewRequest(overlap))
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Fatal("rotation discarded active previous key")
	}
	deletion := &integrationsv1.DeleteDestinationRequest{RequestId: uuid.NewString(), DestinationId: id.String(), ExpectedVersion: 3, Reason: "remove receiver"}
	_, err = f.service.DeleteDestination(f.ctx, connect.NewRequest(deletion))
	requireNoError(t, err)
	_, err = f.service.DeleteDestination(f.ctx, connect.NewRequest(deletion))
	requireNoError(t, err)
	var encrypted, previous []byte
	requireNoError(t, f.conn.QueryRow(f.ctx, "SELECT secret_ciphertext,previous_secret_ciphertext FROM integration_destinations WHERE id=$1", id).Scan(&encrypted, &previous))
	if len(encrypted) != 0 || len(previous) != 0 {
		t.Fatal("delete retained credential ciphertext")
	}
	page, err := f.service.ListDestinations(f.ctx, connect.NewRequest(&integrationsv1.ListDestinationsRequest{}))
	requireNoError(t, err)
	if len(page.Msg.Destinations) != 0 {
		t.Fatal("deleted destination listed")
	}
}

func TestIntegrationAuthorizationValidationAndStableCursor(t *testing.T) {
	f := newIntegrationFixture(t)
	unsigned := context.Background()
	_, err := f.service.ListDestinations(unsigned, connect.NewRequest(&integrationsv1.ListDestinationsRequest{}))
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatal("anonymous read accepted")
	}
	denied := identity.WithPrincipal(f.ctx, identity.Principal{ID: f.actor.ID, Role: "auditor"})
	_, err = f.service.ListDeliveries(denied, connect.NewRequest(&integrationsv1.ListDeliveriesRequest{}))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatal("unprivileged read accepted")
	}
	invalid := &integrationsv1.CreateDestinationRequest{RequestId: uuid.NewString(), Config: &integrationsv1.DestinationConfig{DisplayName: "bad", Kind: integrationsv1.DestinationKind_DESTINATION_KIND_WEBHOOK, Endpoint: "http://plain.example"}, SigningSecret: bytes.Repeat([]byte{1}, 32), Reason: "test"}
	_, err = f.service.CreateDestination(f.ctx, connect.NewRequest(invalid))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatal("plaintext endpoint accepted")
	}
	invalid.Config.Kind = integrationsv1.DestinationKind_DESTINATION_KIND_SYSLOG_TLS
	invalid.Config.Endpoint = "tls://syslog.example:6514"
	invalid.SigningSecret = nil
	_, err = f.service.CreateDestination(f.ctx, connect.NewRequest(invalid))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatal("syslog without pinned CA accepted")
	}
	f.target(t, 1, "https://receiver.example/events", "", bytes.Repeat([]byte{1}, 32))
	for range 3 {
		f.event(t, uuid.NewString())
	}
	page, err := f.service.ListDeliveries(f.ctx, connect.NewRequest(&integrationsv1.ListDeliveriesRequest{PageSize: 1}))
	requireNoError(t, err)
	if len(page.Msg.Deliveries) != 1 || page.Msg.NextPageToken == "" {
		t.Fatal("missing first keyset page")
	}
	newer := f.event(t, "newer")
	next, err := f.service.ListDeliveries(f.ctx, connect.NewRequest(&integrationsv1.ListDeliveriesRequest{PageSize: 100, PageToken: page.Msg.NextPageToken}))
	requireNoError(t, err)
	if len(next.Msg.Deliveries) != 2 {
		t.Fatal("insertion shifted cursor")
	}
	for _, delivery := range next.Msg.Deliveries {
		if delivery.Id == page.Msg.Deliveries[0].Id || delivery.EventId == newer.String() {
			t.Fatal("cursor repeated/newer item")
		}
	}
	_, err = f.service.ListDeliveries(f.ctx, connect.NewRequest(&integrationsv1.ListDeliveriesRequest{Status: integrationsv1.DeliveryStatus_DELIVERY_STATUS_DEAD_LETTER, PageToken: page.Msg.NextPageToken}))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatal("cursor crossed filters")
	}
}

func TestDeliverySummaryCountsRecentDeliveriesAndFailureBacklog(t *testing.T) {
	f := newIntegrationFixture(t)
	target := f.target(t, 1, "https://receiver.example/events", "", bytes.Repeat([]byte{1}, 32))
	other := f.target(t, 1, "https://other.example/events", "", bytes.Repeat([]byte{2}, 32))
	set := func(event uuid.UUID, assignment string, args ...any) {
		t.Helper()
		_, err := f.conn.Exec(f.ctx, "UPDATE integration_deliveries SET "+assignment+" WHERE destination_id=$1 AND event_id=$2", append([]any{target.ID, event}, args...)...)
		requireNoError(t, err)
	}
	recent := f.event(t, "recent")
	set(recent, "status=3, delivered_at=clock_timestamp()-interval '1 hour'")
	old := f.event(t, "old")
	set(old, "status=3, delivered_at=clock_timestamp()-interval '2 days'")
	dead := f.event(t, "dead")
	set(dead, "status=4, attempts=10, last_error='http_status'")
	retrying := f.event(t, "retrying")
	set(retrying, "attempts=2, last_error='connect_failed'")
	queued := f.event(t, "queued")

	denied := identity.WithPrincipal(f.ctx, identity.Principal{ID: f.actor.ID, Role: "auditor"})
	if _, err := f.service.SummarizeDeliveries(denied, connect.NewRequest(&integrationsv1.SummarizeDeliveriesRequest{})); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatal("unprivileged summary accepted")
	}
	summary, err := f.service.SummarizeDeliveries(f.ctx, connect.NewRequest(&integrationsv1.SummarizeDeliveriesRequest{}))
	requireNoError(t, err)
	if summary.Msg.DeliveredSince == nil || time.Since(summary.Msg.DeliveredSince.AsTime()) < 23*time.Hour {
		t.Fatal("summary window is not the last 24 hours")
	}
	counts := map[string]*integrationsv1.DeliverySummary{}
	for _, row := range summary.Msg.Summaries {
		counts[row.DestinationId] = row
	}
	got := counts[target.ID.String()]
	// The retrying delivery is newer than the dead letter, so its reason is the latest.
	if got == nil || got.Delivered != 1 || got.Failed != 1 || got.Retrying != 1 || got.Queued != 1 || got.LastDeliveredAt == nil || got.LastError != "connect_failed" {
		t.Fatalf("summary for receiver %v", got)
	}
	// Every event also fanned out to the other destination, still waiting.
	if peer := counts[other.ID.String()]; peer == nil || peer.Delivered != 0 || peer.Queued != 5 || peer.LastDeliveredAt != nil || peer.LastError != "" {
		t.Fatalf("summary for the other destination %v", peer)
	}

	destination := target.ID.String()
	failures, err := f.service.ListDeliveries(f.ctx, connect.NewRequest(&integrationsv1.ListDeliveriesRequest{DestinationId: &destination, FailuresOnly: true, PageSize: 1}))
	requireNoError(t, err)
	if len(failures.Msg.Deliveries) != 1 || failures.Msg.NextPageToken == "" {
		t.Fatal("missing first failures page")
	}
	rest, err := f.service.ListDeliveries(f.ctx, connect.NewRequest(&integrationsv1.ListDeliveriesRequest{DestinationId: &destination, FailuresOnly: true, PageToken: failures.Msg.NextPageToken}))
	requireNoError(t, err)
	listed := map[uuid.UUID]bool{}
	for _, delivery := range append(failures.Msg.Deliveries, rest.Msg.Deliveries...) {
		listed[uuid.MustParse(delivery.EventId)] = true
	}
	if len(listed) != 2 || !listed[dead] || !listed[retrying] || listed[queued] || listed[recent] || listed[old] {
		t.Fatalf("failures listed %v", listed)
	}
	if _, err = f.service.ListDeliveries(f.ctx, connect.NewRequest(&integrationsv1.ListDeliveriesRequest{DestinationId: &destination, PageToken: failures.Msg.NextPageToken})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatal("failures cursor reused for every delivery")
	}
	if _, err = f.service.ListDeliveries(f.ctx, connect.NewRequest(&integrationsv1.ListDeliveriesRequest{FailuresOnly: true, Status: integrationsv1.DeliveryStatus_DELIVERY_STATUS_DELIVERED})); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatal("failures filter combined with a status filter")
	}
}
