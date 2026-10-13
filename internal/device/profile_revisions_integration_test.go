//go:build integration

package device

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/device/assistance"
	"lindm/internal/device/core"
	"lindm/internal/device/dispatch"
	"lindm/internal/identity"
	"lindm/internal/testdb"
)

func TestListProfileRevisions(t *testing.T) {
	ctx := t.Context()
	pool, conn := testdb.Open(t)
	ca, key := testCA(t, time.Now().Add(24*time.Hour))
	service, err := New(pool, core.Config{DeploymentID: uuid.NewString(), CACertificate: ca, CAKey: key, Identity: localIdentity(t, pool)}, assistance.NewRuntime())
	if err != nil {
		t.Fatal(err)
	}
	owner := insertPrincipal(t, ctx, conn, identity.RoleOwner)
	ownerCtx := identity.WithPrincipal(ctx, owner)
	profileID, head := uuid.New(), uuid.New()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "INSERT INTO profiles (id, head_revision_id, created_at) VALUES ($1,$2,clock_timestamp())", profileID, head); err != nil {
		t.Fatal(err)
	}
	ids := make(map[uint64]string)
	for i := 1; i <= 205; i++ {
		id := uuid.New()
		if i == 205 {
			id = head
		}
		ids[uint64(i)] = id.String()
		if _, err := tx.Exec(ctx, `INSERT INTO profile_revisions (id,profile_id,revision_number,name,description,resource_count,spec_digest,actor_id,published_at) VALUES ($1,$2,$3,$4,'revision description',1,$5,$6,clock_timestamp())`, id, profileID, i, fmt.Sprintf("Revision %d", i), make([]byte, 32), owner.ID); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	request := &adminv1.ListProfileRevisionsRequest{ProfileId: profileID.String(), PageSize: 200}
	if _, err := service.ListProfileRevisions(ctx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("unauthenticated: %v", err)
	}
	if _, err := service.ListProfileRevisions(identity.WithPrincipal(ctx, identity.Principal{ID: owner.ID}), connect.NewRequest(request)); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("ungranted: %v", err)
	}
	first, err := service.ListProfileRevisions(ownerCtx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Msg.GetRevisions()) != 200 || first.Msg.GetNextPageToken() == "" {
		t.Fatalf("first page: %d, token %q", len(first.Msg.GetRevisions()), first.Msg.GetNextPageToken())
	}
	request.PageToken = first.Msg.GetNextPageToken()
	second, err := service.ListProfileRevisions(ownerCtx, connect.NewRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Msg.GetRevisions()) != 5 || second.Msg.GetNextPageToken() != "" {
		t.Fatal("incorrect final page")
	}
	rows := append(first.Msg.GetRevisions(), second.Msg.GetRevisions()...)
	for i, row := range rows {
		number := uint64(205 - i)
		if row.GetRevisionNumber() != number || row.GetRevisionId() != ids[number] || row.GetProfileId() != profileID.String() || row.GetName() != fmt.Sprintf("Revision %d", number) || row.GetDescription() != "revision description" || row.GetActorId() != owner.ID.String() || row.GetResourceCount() != 1 || row.GetPublishedAt() == nil || len(row.GetSpecSha256()) != 32 {
			t.Fatalf("incorrect revision at %d: %v", i, row)
		}
	}
	defaults, err := service.ListProfileRevisions(ownerCtx, connect.NewRequest(&adminv1.ListProfileRevisionsRequest{ProfileId: profileID.String()}))
	if err != nil || len(defaults.Msg.GetRevisions()) != 50 {
		t.Fatalf("default page: %v, %v", defaults, err)
	}
	for _, bad := range []*adminv1.ListProfileRevisionsRequest{
		{ProfileId: profileID.String(), PageSize: 201},
		{ProfileId: uuid.Nil.String()},
		{ProfileId: profileID.String(), PageToken: "invalid"},
		{ProfileId: profileID.String(), PageToken: strings.Repeat("a", 513)},
		{ProfileId: uuid.NewString(), PageToken: first.Msg.GetNextPageToken()},
	} {
		if _, err := service.ListProfileRevisions(ownerCtx, connect.NewRequest(bad)); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Fatalf("invalid request: %v", err)
		}
	}
	unknown := uuid.NewString()
	_, missing := service.ListProfileRevisions(ownerCtx, connect.NewRequest(&adminv1.ListProfileRevisionsRequest{ProfileId: unknown}))
	_, getMissing := service.GetProfileRevision(ownerCtx, connect.NewRequest(&adminv1.GetProfileRevisionRequest{ProfileId: unknown}))
	if connect.CodeOf(missing) != connect.CodeNotFound || missing.Error() != getMissing.Error() {
		t.Fatalf("unknown differs: %v / %v", missing, getMissing)
	}
	empty, err := service.ListProfileRevisions(ownerCtx, connect.NewRequest(&adminv1.ListProfileRevisionsRequest{ProfileId: profileID.String(), PageToken: dispatch.EncodeProfileRevisionCursor(profileID, 1)}))
	if err != nil || len(empty.Msg.GetRevisions()) != 0 || empty.Msg.GetNextPageToken() != "" {
		t.Fatalf("exhausted: %v, %v", empty, err)
	}
	// Metadata can expand substantially in JSON; byte-budget truncation must preserve the cursor.
	if _, err := conn.Exec(ctx, "UPDATE profile_revisions SET description=$1 WHERE profile_id=$2", strings.Repeat("\x01", 4096), profileID); err != nil {
		t.Fatal(err)
	}
	token := ""
	count := 0
	for {
		page, err := service.ListProfileRevisions(ownerCtx, connect.NewRequest(&adminv1.ListProfileRevisionsRequest{ProfileId: profileID.String(), PageSize: 200, PageToken: token}))
		if err != nil {
			t.Fatal(err)
		}
		data, err := protojson.Marshal(page.Msg)
		if err != nil {
			t.Fatal(err)
		}
		if len(data) > core.MaxMessageBytes || len(page.Msg.GetRevisions()) == 0 {
			t.Fatal("unbounded or empty page")
		}
		for _, row := range page.Msg.GetRevisions() {
			if row.GetRevisionNumber() != uint64(205-count) {
				t.Fatal("byte budget lost or repeated revision")
			}
			count++
		}
		next := page.Msg.GetNextPageToken()
		if next == "" {
			break
		}
		if next == token || count >= 205 {
			t.Fatal("cursor failed to advance")
		}
		token = next
	}
	if count != 205 {
		t.Fatalf("lost revisions: %d", count)
	}
}
