package devlab

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	configv1 "lindm/gen/lindm/config/v1"
	policyv1 "lindm/gen/lindm/policy/v1"
	"lindm/internal/config"
)

// ProfileCatalogEvidence records catalog behavior, not assignment, execution or
// device compliance. The fixture owns a real server and disposable database.
type ProfileCatalogEvidence struct {
	IsolatedDatabase          string                          `json:"isolated_database"`
	ProtectedOnlineKeysLoaded bool                            `json:"protected_online_keys_loaded"`
	Initial                   *adminv1.ServiceProfileRevision `json:"initial_revision"`
	Current                   *adminv1.ServiceProfileRevision `json:"current_revision"`
	ImmutableHistory          bool                            `json:"immutable_history"`
	ExactRetryAfterRestart    bool                            `json:"exact_retry_after_restart"`
	StaleHeadRejected         bool                            `json:"stale_head_rejected"`
	ChangedRequestRejected    bool                            `json:"changed_request_rejected"`
	TypedDependenciesRetained bool                            `json:"typed_dependencies_retained"`
	CatalogHeadListed         bool                            `json:"catalog_head_listed"`
}

func CheckProfileCatalog(ctx context.Context, repository, binary string) (_ *ProfileCatalogEvidence, resultErr error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	fixture, err := OpenAuthorityFixture(ctx, repository, binary)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, fixture.Close()) }()
	if err := restartWithCatalogSigningKeys(ctx, fixture); err != nil {
		return nil, err
	}
	owner, err := fixture.OpenOwnerSession(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer cancel()
		resultErr = errors.Join(resultErr, owner.Close(cleanup))
	}()
	ids := []string{uuid.NewString(), uuid.NewString()}
	slices.Sort(ids)
	request := &adminv1.PublishServiceProfileRevisionRequest{
		RequestId: uuid.NewString(), ProfileId: uuid.NewString(), Reason: "qualify immutable service profile publication",
		Spec: &policyv1.ServiceProfileSpec{Name: "Native service catalog qualification", Description: "Catalog evidence only; no devices are assigned.", Resources: []*policyv1.ServiceProfileResource{
			{ResourceId: ids[0], Desired: &agentv1.ServiceDesiredState{Unit: "catalog-prerequisite.service", Runtime: agentv1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE, Enablement: agentv1.ServiceEnablement_SERVICE_ENABLEMENT_UNMANAGED}},
			{ResourceId: ids[1], Desired: &agentv1.ServiceDesiredState{Unit: "catalog-dependent.service", Runtime: agentv1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE, Enablement: agentv1.ServiceEnablement_SERVICE_ENABLEMENT_ENABLED}, DependsOn: []string{ids[0]}},
		}},
	}
	first, err := owner.Admin.PublishServiceProfileRevision(ctx, connect.NewRequest(request))
	if err != nil {
		return nil, fmt.Errorf("publish initial catalog revision: %w", err)
	}
	if first.Msg.GetRevision().GetProfileId() != request.GetProfileId() || first.Msg.GetRevision().GetRevisionNumber() != 1 || !proto.Equal(first.Msg.GetRevision().GetSpec(), request.GetSpec()) {
		return nil, errors.New("initial catalog revision differs from typed submitted resources")
	}
	evidence := &ProfileCatalogEvidence{IsolatedDatabase: fixture.DatabaseName, ProtectedOnlineKeysLoaded: true, Initial: first.Msg.GetRevision()}
	next := proto.CloneOf(request)
	next.RequestId = uuid.NewString()
	next.ExpectedRevisionId = proto.String(evidence.Initial.GetRevisionId())
	next.Spec.Name = "Revised native service catalog qualification"
	next.Spec.Resources[1].Desired.Runtime = agentv1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_INACTIVE
	second, err := owner.Admin.PublishServiceProfileRevision(ctx, connect.NewRequest(next))
	if err != nil {
		return nil, fmt.Errorf("publish next catalog revision: %w", err)
	}
	if second.Msg.GetRevision().GetRevisionNumber() != 2 || second.Msg.GetRevision().GetRevisionId() == evidence.Initial.GetRevisionId() || !proto.Equal(second.Msg.GetRevision().GetSpec(), next.GetSpec()) {
		return nil, errors.New("next catalog publication did not retain distinct typed revision")
	}
	evidence.Current = second.Msg.GetRevision()
	stale := proto.CloneOf(next)
	stale.RequestId = uuid.NewString()
	if _, err := owner.Admin.PublishServiceProfileRevision(ctx, connect.NewRequest(stale)); connect.CodeOf(err) != connect.CodeAborted {
		return nil, fmt.Errorf("stale catalog head was not rejected: %w", err)
	}
	evidence.StaleHeadRejected = true
	changed := proto.CloneOf(request)
	changed.Spec.Name = "changed request identity"
	if _, err := owner.Admin.PublishServiceProfileRevision(ctx, connect.NewRequest(changed)); connect.CodeOf(err) != connect.CodeAborted {
		return nil, fmt.Errorf("changed catalog request was not rejected: %w", err)
	}
	evidence.ChangedRequestRejected = true
	if err := fixture.Restart(ctx); err != nil {
		return nil, err
	}
	replay, err := owner.Admin.PublishServiceProfileRevision(ctx, connect.NewRequest(request))
	if err != nil {
		return nil, fmt.Errorf("retry catalog publication after server restart: %w", err)
	}
	if !proto.Equal(replay.Msg.GetRevision(), evidence.Initial) {
		return nil, errors.New("restarted server did not retain original catalog receipt")
	}
	evidence.ExactRetryAfterRestart = true
	historical, err := owner.Admin.GetServiceProfileRevision(ctx, connect.NewRequest(&adminv1.GetServiceProfileRevisionRequest{ProfileId: request.GetProfileId(), RevisionId: proto.String(evidence.Initial.GetRevisionId())}))
	if err != nil {
		return nil, err
	}
	if !proto.Equal(historical.Msg.GetRevision(), evidence.Initial) {
		return nil, errors.New("later catalog publication rewrote immutable history")
	}
	evidence.ImmutableHistory = true
	evidence.TypedDependenciesRetained = proto.Equal(historical.Msg.GetRevision().GetSpec(), request.GetSpec())
	head, err := owner.Admin.GetServiceProfileRevision(ctx, connect.NewRequest(&adminv1.GetServiceProfileRevisionRequest{ProfileId: request.GetProfileId()}))
	if err != nil {
		return nil, err
	}
	if !proto.Equal(head.Msg.GetRevision(), evidence.Current) {
		return nil, errors.New("historical retry rewound the catalog head")
	}
	list, err := owner.Admin.ListServiceProfiles(ctx, connect.NewRequest(&adminv1.ListServiceProfilesRequest{PageSize: 1}))
	if err != nil {
		return nil, err
	}
	if len(list.Msg.GetProfiles()) != 1 || list.Msg.GetProfiles()[0].GetProfileId() != request.GetProfileId() || list.Msg.GetProfiles()[0].GetRevisionId() != evidence.Current.GetRevisionId() || list.Msg.GetProfiles()[0].GetResourceCount() != 2 || list.Msg.GetNextPageToken() != "" {
		return nil, errors.New("catalog list did not expose the current immutable head")
	}
	evidence.CatalogHeadListed = true
	return evidence, nil
}

// These fresh, undelegated online keys exercise actual server resource loading,
// not issuance. Offline development keys never enter the server configuration.
func restartWithCatalogSigningKeys(ctx context.Context, fixture *AuthorityFixture) error {
	for _, name := range []string{"catalog-plan.pem", "catalog-start.pem"} {
		if err := writeCatalogSigningKey(filepath.Join(fixture.directory, name)); err != nil {
			return err
		}
	}
	document, err := config.Load(fixture.configPath())
	if err != nil {
		return err
	}
	document.Proto.ExecutionSigning = &configv1.ExecutionSigningConfig{
		PlanKeyFile: "catalog-plan.pem", StartKeyFile: "catalog-start.pem",
	}
	encoded, err := protojson.Marshal(document.Proto)
	if err != nil {
		return err
	}
	if err := os.WriteFile(fixture.configPath(), encoded, 0600); err != nil {
		return err
	}
	return fixture.Restart(ctx)
}

func writeCatalogSigningKey(path string) error {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	defer clear(key)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	defer clear(der)
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	defer clear(encoded)
	return os.WriteFile(path, encoded, 0600)
}
