// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	adminv1 "lindm/gen/lindm/admin/v1"
	authv1 "lindm/gen/lindm/auth/v1"
	orgv1 "lindm/gen/lindm/org/v1"
	"lindm/internal/ctl"
	"lindm/internal/orgapply"
)

func runtimeAuthorizationScope(ctx context.Context, owner, second *OwnerSession, deviceID string) (resultErr error) {
	if err := second.Close(ctx); err != nil {
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, owner.UpdateAccount(context.WithoutCancel(ctx), &authv1.UpdateAccountRequest{AccountId: second.AccountID, Enabled: true, Role: "owner"}))
	}()
	scopeID := deviceID
	if scopeID == "" {
		scopeID = uuid.NewString()
	}
	if err := owner.UpdateAccount(ctx, &authv1.UpdateAccountRequest{AccountId: second.AccountID, Enabled: true, Role: "runtime-reader", Scopes: []*authv1.DeviceScope{{DeviceIds: []string{scopeID}}}}); err != nil {
		return err
	}
	if err := second.localCeremonyRole(ctx, "", "runtime-reader"); err != nil {
		return err
	}
	if deviceID != "" {
		if _, err := second.Admin.GetDevice(ctx, connect.NewRequest(&adminv1.GetDeviceRequest{DeviceId: deviceID})); err != nil {
			return fmt.Errorf("scoped reader could not read enrolled target: %w", err)
		}
	}
	current, err := owner.Admin.GetAuthorization(ctx, connect.NewRequest(&adminv1.GetAuthorizationRequest{}))
	if err != nil {
		return err
	}
	request := &adminv1.UpdateAuthorizationRequest{RequestId: uuid.NewString(), ExpectedRevision: current.Msg.GetAuthorization().GetRevision(), Policy: current.Msg.GetAuthorization().GetPolicy(), Reason: "scoped non-owner must not mutate authorization"}
	if _, err := second.Admin.UpdateAuthorization(ctx, connect.NewRequest(request)); connect.CodeOf(err) != connect.CodePermissionDenied {
		return fmt.Errorf("non-owner policy update: expected permission_denied, got %v", err)
	}
	if err := owner.UpdateAccount(ctx, &authv1.UpdateAccountRequest{AccountId: second.AccountID, Enabled: true, Role: "runtime-reader", Scopes: []*authv1.DeviceScope{{DeviceIds: []string{uuid.NewString()}}}}); err != nil {
		return err
	}
	if _, err := second.Admin.ListDevices(ctx, connect.NewRequest(&adminv1.ListDevicesRequest{})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		return fmt.Errorf("account scope fence: expected unauthenticated, got %v", err)
	}
	if err := second.Close(ctx); err != nil {
		return err
	}
	if err := second.localCeremonyRole(ctx, "", "runtime-reader"); err != nil {
		return err
	}
	if deviceID != "" {
		if _, err := second.Admin.GetDevice(ctx, connect.NewRequest(&adminv1.GetDeviceRequest{DeviceId: deviceID})); connect.CodeOf(err) != connect.CodeNotFound {
			return fmt.Errorf("off-scope enrolled target: expected not_found, got %v", err)
		}
	}
	policy := proto.CloneOf(current.Msg.GetAuthorization().GetPolicy())
	policy.Roles = append(policy.Roles, &authv1.RoleDefinition{Name: "fence-witness", Permissions: []string{"fleet.read"}})
	request.RequestId, request.Policy, request.Reason = uuid.NewString(), policy, "runtime update fences existing non-owner console session"
	if _, err := owner.Admin.UpdateAuthorization(ctx, connect.NewRequest(request)); err != nil {
		return err
	}
	if _, err := second.Admin.ListDevices(ctx, connect.NewRequest(&adminv1.ListDevicesRequest{})); connect.CodeOf(err) != connect.CodeUnauthenticated {
		return fmt.Errorf("runtime session fence: expected unauthenticated, got %v", err)
	}
	return nil
}

func runtimeAuthorizationOrganization(ctx context.Context, fixture *AuthorityFixture, owner *OwnerSession) (resultErr error) {
	state, err := owner.Admin.GetAuthorization(ctx, connect.NewRequest(&adminv1.GetAuthorizationRequest{}))
	if err != nil {
		return err
	}
	policy := proto.CloneOf(state.Msg.GetAuthorization().GetPolicy())
	policy.Roles = append(policy.Roles, &authv1.RoleDefinition{Name: "organization-reader", Permissions: []string{"fleet.read"}})
	organization := &orgv1.Organization{Name: "runtime-qualification", Authorization: policy, Accounts: []*authv1.CreateAccountRequest{{Username: "runtime-browser-reader", Role: "organization-reader"}}}
	preview, err := owner.ApplyOrganization(ctx, &orgv1.ApplyOrganizationRequest{Organization: organization})
	if err != nil {
		return err
	}
	if len(preview.GetPlanSha256()) != sha256.Size || len(preview.GetSecrets()) != 0 {
		return errors.New("browser preview missing review digest or exposed secrets")
	}
	first, err := owner.ApplyOrganization(ctx, &orgv1.ApplyOrganizationRequest{Organization: organization, Apply: true, ExpectedPlanSha256: preview.GetPlanSha256()})
	if err != nil {
		return err
	}
	defer clearOrganizationSecrets(first)
	if first.GetFailureCode() != "" || len(first.GetSecrets()) != 1 || first.GetSecrets()[0].GetSecret() == "" {
		return errors.New("browser organization did not issue exactly one account enrollment")
	}
	preview, err = owner.ApplyOrganization(ctx, &orgv1.ApplyOrganizationRequest{Organization: organization})
	if err != nil {
		return err
	}
	repeated, err := owner.ApplyOrganization(ctx, &orgv1.ApplyOrganizationRequest{Organization: organization, Apply: true, ExpectedPlanSha256: preview.GetPlanSha256()})
	if err != nil {
		return err
	}
	defer clearOrganizationSecrets(repeated)
	if repeated.GetFailureCode() != "" || len(repeated.GetSecrets()) != 0 {
		return errors.New("unchanged browser apply failed or repeated a one-time secret")
	}
	// The second account fails at the real account authority, after the first
	// issuance committed. The response must preserve that first shown-once secret.
	partialSpec := &orgv1.Organization{Name: "partial-runtime-qualification", Accounts: []*authv1.CreateAccountRequest{
		{Username: "runtime-partial-reader", Role: "auditor"},
		{Username: "runtime-invalid-reader", Role: "runtime-missing-role"},
	}}
	partialPreview, err := owner.ApplyOrganization(ctx, &orgv1.ApplyOrganizationRequest{Organization: partialSpec})
	if err != nil {
		return err
	}
	partial, err := owner.ApplyOrganization(ctx, &orgv1.ApplyOrganizationRequest{Organization: partialSpec, Apply: true, ExpectedPlanSha256: partialPreview.GetPlanSha256()})
	if err != nil {
		return err
	}
	defer clearOrganizationSecrets(partial)
	if partial.GetFailureCode() == "" || len(partial.GetSecrets()) != 1 || partial.GetSecrets()[0].GetSecret() == "" || len(partial.GetOutcomes()) != 1 {
		return errors.New("partial browser apply lost committed outcome or shown-once secret")
	}

	directory, err := os.MkdirTemp("", "lindm-runtime-cli-")
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, os.RemoveAll(directory)) }()
	ca, err := os.ReadFile(filepath.Join(fixture.transportTrustDirectory(), "transport-ca.crt"))
	if err != nil {
		return err
	}
	configPath := filepath.Join(directory, "cli.json")
	client, err := ctl.New(configPath, &authv1.CLIConfig{ServerOrigin: fixture.ConsoleOrigin, CaPem: string(ca)})
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, client.Close()) }()
	if err := client.Login(ctx, owner.ApproveCLI); err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, client.Logout(context.WithoutCancel(ctx))) }()
	if err := runtimeAuthorizationBearerBoundary(ctx, owner, configPath); err != nil {
		return err
	}
	organization.Authorization.Roles = append(organization.Authorization.Roles, &authv1.RoleDefinition{Name: "cli-reader", Permissions: []string{"fleet.read"}})
	organization.Accounts = []*authv1.CreateAccountRequest{{Username: "runtime-cli-forbidden", Role: "cli-reader"}}
	encoded, err := protojson.Marshal(organization)
	if err != nil {
		return err
	}
	specPath := filepath.Join(directory, "organization.json")
	if err := os.WriteFile(specPath, encoded, 0600); err != nil {
		return err
	}
	var output bytes.Buffer
	if err := ctl.Run(ctx, []string{"apply", "-config", configPath, "-f", specPath, "-o", "json"}, &output, nil); err != nil {
		return err
	}
	var applied struct {
		Outcomes []orgapply.Outcome `json:"outcomes"`
	}
	if err := json.Unmarshal(output.Bytes(), &applied); err != nil {
		return err
	}
	var pending bool
	for _, outcome := range applied.Outcomes {
		if outcome.Kind == "account" {
			if outcome.Status != "pending" {
				return errors.New("CLI claimed browser account authority")
			}
			pending = true
		}
	}
	if !pending {
		return errors.New("CLI omitted account authority refusal")
	}
	observed, err := client.Admin().GetAuthorization(ctx, connect.NewRequest(&adminv1.GetAuthorizationRequest{}))
	if err != nil {
		return err
	}
	if !proto.Equal(observed.Msg.GetAuthorization().GetPolicy(), organization.GetAuthorization()) {
		return errors.New("CLI failed to apply runtime authorization")
	}
	accounts, err := owner.ListAccounts(ctx)
	if err != nil {
		return err
	}
	for _, account := range accounts.GetAccounts() {
		if account.GetUsername() == "runtime-cli-forbidden" {
			return errors.New("CLI created a browser-only account")
		}
	}
	return nil
}

func runtimeAuthorizationBearerBoundary(ctx context.Context, owner *OwnerSession, configPath string) error {
	encoded, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	defer clear(encoded)
	config := new(authv1.CLIConfig)
	if err := protojson.Unmarshal(encoded, config); err != nil {
		return err
	}
	defer func() { config.SessionToken = "" }()
	// No cookie jar: the real CLI bearer alone must never acquire browser
	// account authority, even with a valid Origin and another session's CSRF.
	client := &http.Client{Transport: owner.transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, probe := range []struct{ path, body string }{
		{"/auth/organization/apply", `{"organization":{"name":"bearer-only","accounts":[{"username":"runtime-cli-forbidden","role":"auditor"}]}}`},
		{"/auth/accounts/create", `{"username":"runtime-cli-forbidden","role":"auditor"}`},
	} {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, owner.origin+probe.path, bytes.NewBufferString(probe.body))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+config.GetSessionToken())
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", owner.origin)
		req.Header.Set("X-CSRF-Token", owner.csrf)
		response, err := client.Do(req)
		if err != nil {
			return errors.New("CLI browser authority probe failed")
		}
		if err := response.Body.Close(); err != nil {
			return err
		}
		if response.StatusCode != http.StatusUnauthorized && response.StatusCode != http.StatusForbidden {
			return fmt.Errorf("CLI bearer browser boundary: HTTP %d", response.StatusCode)
		}
	}
	return nil
}
