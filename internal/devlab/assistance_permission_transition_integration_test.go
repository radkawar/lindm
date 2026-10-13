//go:build integration

package devlab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/config"
	"lindm/internal/identity/identitydb"
)

// These are explicit old/new operator documents, not a product compatibility
// mapper. Each server independently validates its own permission vocabulary.
func assistanceTransitionPolicies() (original, interim, restored *authv1.AuthorizationPolicy) {
	original = &authv1.AuthorizationPolicy{
		Roles: []*authv1.RoleDefinition{
			{Name: "legacy-empty", Permissions: []string{"remote_assistance.run"}},
			{Name: "legacy-mixed", Permissions: []string{"fleet.read", "remote_assistance.run", "remote_assistance.clipboard", "remote_assistance.keyboard", "remote_assistance.display", "remote_assistance.message"}},
			{Name: "unrelated-reader", Permissions: []string{"fleet.read"}},
		},
		ApprovalRequiredPermissions: []string{"actions.lock"},
	}
	interim = proto.CloneOf(original)
	interim.Roles = interim.Roles[1:]
	interim.Roles[0].Permissions = []string{"fleet.read", "remote_assistance.clipboard", "remote_assistance.keyboard", "remote_assistance.display", "remote_assistance.message"}
	restored = proto.CloneOf(original)
	restored.Roles[0].Permissions = []string{"remote_assistance.view", "remote_assistance.control"}
	restored.Roles[1].Permissions = []string{"fleet.read", "remote_assistance.view", "remote_assistance.control", "remote_assistance.clipboard", "remote_assistance.keyboard", "remote_assistance.display", "remote_assistance.message"}
	return original, interim, restored
}

type assistanceTransitionReceipt struct {
	Scenario               string                      `json:"scenario"`
	Passed                 bool                        `json:"passed"`
	OldBinary              assistanceTransitionBinary  `json:"old_binary"`
	NewBinary              assistanceTransitionBinary  `json:"new_binary"`
	OwnerID                string                      `json:"owner_id"`
	InitialRevision        uint64                      `json:"initial_revision"`
	InterimRevision        uint64                      `json:"interim_revision"`
	FinalRevision          uint64                      `json:"final_revision"`
	Original               *adminv1.AuthorizationState `json:"original"`
	Interim                *adminv1.AuthorizationState `json:"interim"`
	Final                  *adminv1.AuthorizationState `json:"final"`
	Actors                 []assistanceTransitionActor `json:"actors"`
	Checks                 []string                    `json:"checks"`
	OriginalResponseSHA256 string                      `json:"original_response_sha256"`
	RetainedResponseSHA256 string                      `json:"retained_response_sha256"`
	OriginalAudit          *adminv1.AuditEvent         `json:"original_audit"`
	RetainedAudit          *adminv1.AuditEvent         `json:"retained_audit"`
	InterimAudit           *adminv1.AuditEvent         `json:"interim_audit"`
	FinalAudit             *adminv1.AuditEvent         `json:"final_audit"`
	InterveningActorID     string                      `json:"intervening_actor_id,omitempty"`
	ScopeBoundary          string                      `json:"scope_boundary"`
}

// Required qualification inputs are actual pre-cutover and post-cutover lindmd
// executables. Ordinary integration without the old executable is not proof.
func TestAssistancePersistedPermissionTransition(t *testing.T) {
	oldBinary := os.Getenv("LINDM_ASSISTANCE_PREVIOUS_SERVER_BINARY")
	if oldBinary == "" {
		t.Skip("requires an actual pre-cutover Tier1/runtime-policy lindmd; no transition qualification claimed")
	}
	newBinary, repository := nativeServer(t)
	oldProof, newProof := assistanceTransitionBinaryProof(t, oldBinary), assistanceTransitionBinaryProof(t, newBinary)
	if oldProof.SHA256 == newProof.SHA256 {
		t.Fatal("transition requires different actual old/new server binaries")
	}
	directory := os.Getenv("LINDM_ASSISTANCE_TRANSITION_EVIDENCE")
	if directory != "" {
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, scenario := range []string{"restore-after-interruption", "reject-intervening-policy-write"} {
		t.Run(scenario, func(t *testing.T) {
			receipt := &assistanceTransitionReceipt{Scenario: scenario, OldBinary: oldProof, NewBinary: newProof, ScopeBoundary: "Real HTTPS local-owner and scoped local-account ceremonies plus PostgreSQL persistence; no native desktop or directory-binding qualification."}
			t.Cleanup(func() { writeAssistanceTransitionReceipt(t, directory, receipt) })
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
			t.Cleanup(cancel)
			fixture, err := OpenLocalConsoleAuthorityFixture(ctx, repository, oldBinary)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := fixture.Close(); err != nil {
					t.Error(err)
				}
			})
			exerciseAssistancePermissionTransition(t, ctx, fixture, newBinary, receipt)
		})
	}
}

func exerciseAssistancePermissionTransition(t *testing.T, ctx context.Context, fixture *AuthorityFixture, newBinary string, receipt *assistanceTransitionReceipt) {
	t.Helper()
	original, interim, restored := assistanceTransitionPolicies()
	owner := assistanceTransitionOwner(t, ctx, fixture)
	receipt.OwnerID = owner.AccountID
	initial := assistanceTransitionState(t, ctx, owner)
	receipt.InitialRevision = initial.GetRevision()
	seed := &adminv1.UpdateAuthorizationRequest{RequestId: uuid.NewString(), ExpectedRevision: initial.GetRevision(), Policy: original, Reason: "assistance transition original authority " + uuid.NewString()}
	originalState := assistanceTransitionUpdate(t, ctx, owner, seed)
	receipt.Original = originalState
	receipt.OriginalAudit = assistanceTransitionAudit(t, ctx, owner, seed.GetReason())
	connection := assistanceTransitionDatabase(t, ctx, fixture)
	stored := assistanceTransitionStoredRequest(t, ctx, connection, owner.AccountID, seed.GetRequestId())
	digest := sha256.Sum256(stored.Response)
	receipt.OriginalResponseSHA256 = hex.EncodeToString(digest[:])
	actors := assistanceTransitionEnrollActors(t, ctx, fixture, owner, receipt)
	document, err := config.Load(fixture.configPath())
	if err != nil {
		t.Fatal(err)
	}
	document.Proto.Authorization = proto.CloneOf(original)
	assistanceTransitionWriteConfig(t, fixture, document)
	interimRequest := &adminv1.UpdateAuthorizationRequest{RequestId: uuid.NewString(), ExpectedRevision: originalState.GetRevision(), Policy: interim, Reason: "explicit assistance permission deny window"}
	withdrawn := assistanceTransitionUpdate(t, ctx, owner, interimRequest)
	receipt.InterimRevision, receipt.Interim = withdrawn.GetRevision(), withdrawn
	receipt.InterimAudit = assistanceTransitionAudit(t, ctx, owner, interimRequest.GetReason())
	if err := fixture.Restart(ctx); err != nil {
		t.Fatal(err)
	}
	owner = assistanceTransitionOwner(t, ctx, fixture)
	assistanceTransitionAssertState(t, assistanceTransitionState(t, ctx, owner), interim, receipt.InterimRevision)
	assistanceTransitionAssertWithdrawn(t, ctx, actors, receipt, "old-server-after-interruption")
	receipt.Checks = append(receipt.Checks, "old server resumes with explicit deny-window policy despite old bootstrap grants")

	// Deploy valid new syntax without allowing bootstrap to restore the grants.
	document.Proto.Authorization = proto.CloneOf(restored)
	assistanceTransitionWriteConfig(t, fixture, document)
	fixture.binary = newBinary
	if err := fixture.Restart(ctx); err != nil {
		t.Fatal(err)
	}
	owner = assistanceTransitionOwner(t, ctx, fixture)
	if owner.AccountID != receipt.OwnerID {
		t.Fatal("restart replaced the preserved owner")
	}
	assistanceTransitionAssertState(t, assistanceTransitionState(t, ctx, owner), interim, receipt.InterimRevision)
	assistanceTransitionAssertWithdrawn(t, ctx, actors, receipt, "new-server-before-restore")
	receipt.Checks = append(receipt.Checks, "new binary preserves interim revision and deny window over new bootstrap grants", "preserved owner authenticates afresh after deployment")
	finishAssistancePermissionTransition(t, ctx, fixture, owner, actors, restored, receipt)
	assistanceTransitionAssertAccounts(t, ctx, owner, actors)
	receipt.Checks = append(receipt.Checks, "account IDs, recorded roles and independent device scopes remain unchanged")
	retained := assistanceTransitionStoredRequest(t, ctx, connection, owner.AccountID, seed.GetRequestId())
	if !bytes.Equal(stored.RequestDigest, retained.RequestDigest) || !bytes.Equal(stored.Response, retained.Response) {
		t.Fatal("permission cutover rewrote the immutable old request receipt")
	}
	digest = sha256.Sum256(retained.Response)
	receipt.RetainedResponseSHA256 = hex.EncodeToString(digest[:])
	receipt.RetainedAudit = assistanceTransitionAudit(t, ctx, owner, seed.GetReason())
	if !proto.Equal(receipt.OriginalAudit, receipt.RetainedAudit) {
		t.Fatal("permission cutover rewrote the original audit event")
	}
	receipt.Checks = append(receipt.Checks, "old request digest/response bytes and original audit event remain unchanged")
}

func finishAssistancePermissionTransition(t *testing.T, ctx context.Context, fixture *AuthorityFixture, owner *OwnerSession, actors []*OwnerSession, restored *authv1.AuthorizationPolicy, receipt *assistanceTransitionReceipt) {
	t.Helper()
	request := &adminv1.UpdateAuthorizationRequest{RequestId: uuid.NewString(), ExpectedRevision: receipt.InterimRevision, Policy: restored, Reason: "explicit assistance grant restoration pinned to interim receipt"}
	if receipt.Scenario == "reject-intervening-policy-write" {
		changed := proto.CloneOf(receipt.Interim.GetPolicy())
		changed.Roles[1].Permissions = append(changed.Roles[1].Permissions, "audit.read")
		second, err := fixture.OpenApproverSession(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(second.transport.CloseIdleConnections)
		if second.AccountID == owner.AccountID {
			t.Fatal("intervening policy writer is not an independent owner")
		}
		receipt.InterveningActorID = second.AccountID
		intervening := &adminv1.UpdateAuthorizationRequest{RequestId: uuid.NewString(), ExpectedRevision: receipt.InterimRevision, Policy: changed, Reason: "independent policy edit during assistance deny window"}
		advanced := assistanceTransitionUpdate(t, ctx, second, intervening)
		receipt.FinalAudit = assistanceTransitionAudit(t, ctx, second, intervening.GetReason())
		if _, err := owner.Admin.UpdateAuthorization(ctx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodeAborted {
			t.Fatalf("stale saved-revision restore: expected aborted, got %v", err)
		}
		current := assistanceTransitionState(t, ctx, owner)
		assistanceTransitionAssertState(t, current, changed, advanced.GetRevision())
		receipt.FinalRevision, receipt.Final = current.GetRevision(), current
		assistanceTransitionAssertWithdrawn(t, ctx, actors, receipt, "after-stale-restore-rejection")
		receipt.Checks = append(receipt.Checks, "intervening policy edit aborts saved-revision restoration without replanning or overwriting it")
		return
	}
	final := assistanceTransitionUpdate(t, ctx, owner, request)
	assistanceTransitionAssertState(t, final, restored, receipt.InterimRevision+1)
	receipt.FinalRevision, receipt.Final = final.GetRevision(), final
	receipt.FinalAudit = assistanceTransitionAudit(t, ctx, owner, request.GetReason())
	for index, actor := range actors {
		role := restored.GetRoles()[index]
		assistanceTransitionLogin(t, ctx, actor, role.GetName())
		receipt.Actors = append(receipt.Actors, assistanceTransitionObserveActor(t, ctx, actor, "restored", role.GetPermissions()))
	}
	legacy := proto.CloneOf(request)
	legacy.RequestId, legacy.ExpectedRevision, legacy.Policy = uuid.NewString(), final.GetRevision(), receipt.Original.GetPolicy()
	if _, err := owner.Admin.UpdateAuthorization(ctx, connect.NewRequest(legacy)); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("new server accepted removed permission: %v", err)
	}
	assistanceTransitionAssertState(t, assistanceTransitionState(t, ctx, owner), restored, final.GetRevision())
	receipt.Checks = append(receipt.Checks, "explicit view/control restoration preserves account scopes and pre-existing capabilities", "new server rejects removed grant without changing current revision")
}

func writeAssistanceTransitionReceipt(t *testing.T, directory string, receipt *assistanceTransitionReceipt) {
	t.Helper()
	receipt.Passed = !t.Failed()
	if directory == "" {
		return
	}
	body, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		t.Error(err)
		return
	}
	path := filepath.Join(directory, receipt.Scenario+".json")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Error(err)
		return
	}
	_, writeErr := file.Write(body)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		t.Errorf("write transition evidence: %v %v", writeErr, closeErr)
	}
}

func assistanceTransitionWriteConfig(t *testing.T, fixture *AuthorityFixture, document *config.Document) {
	t.Helper()
	body, err := protojson.Marshal(document.Proto)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(body)
	if err := fixture.writeConfig(body); err != nil {
		t.Fatal(err)
	}
}

func assistanceTransitionDatabase(t *testing.T, ctx context.Context, fixture *AuthorityFixture) *pgx.Conn {
	t.Helper()
	cfg := fixture.database.admin.Copy()
	cfg.Database = fixture.DatabaseName
	connection, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal("open owned transition receipt reader failed")
	}
	t.Cleanup(func() {
		if err := connection.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	return connection
}

func assistanceTransitionStoredRequest(t *testing.T, ctx context.Context, connection *pgx.Conn, actorID, requestID string) identitydb.ReadAuthorizationRequestRow {
	t.Helper()
	row, err := identitydb.New(connection).ReadAuthorizationRequest(ctx, identitydb.ReadAuthorizationRequestParams{ActorID: uuid.MustParse(actorID), RequestID: uuid.MustParse(requestID)})
	if err != nil {
		t.Fatal(err)
	}
	return row
}
