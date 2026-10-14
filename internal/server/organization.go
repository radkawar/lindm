// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"errors"
	"io"
	"net/http"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"

	adminv1connect "lindm/gen/lindm/admin/v1/adminv1connect"
	orgv1 "lindm/gen/lindm/org/v1"
	"lindm/internal/device/core"
	"lindm/internal/identity"
	"lindm/internal/orgapply"
)

// organizationHandler reuses the declarative engine with a real browser capability.
// It is mounted outside the CLI bearer allowlist, behind exact Origin and CSRF.
func organizationHandler(auth *identity.Service, admin adminv1connect.AdminServiceClient) (http.Handler, error) {
	rules, err := protovalidate.New(protovalidate.WithMessages(&orgv1.ApplyOrganizationRequest{}))
	if err != nil {
		return nil, err
	}
	return auth.RequireSession(core.WithAdminAdmission(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<20))
		request := new(orgv1.ApplyOrganizationRequest)
		if err != nil || protojson.Unmarshal(body, request) != nil || rules.Validate(request) != nil {
			http.Error(w, "Invalid organization file", http.StatusBadRequest)
			return
		}
		accounts := auth.BrowserAccounts()
		plan, err := orgapply.Plan(r.Context(), admin, request.GetOrganization())
		if err == nil {
			err = plan.PreviewAccounts(r.Context(), accounts)
		}
		if err != nil {
			writeOrganizationResponse(w, &orgv1.ApplyOrganizationResponse{FailureCode: organizationFailureCode(err), FailureReason: "organization_review_failed"})
			return
		}
		digest, err := plan.Digest()
		if err != nil {
			http.Error(w, "Couldn't prepare the organization review", http.StatusInternalServerError)
			return
		}
		response := &orgv1.ApplyOrganizationResponse{PlanSha256: digest}
		outcomes := plan.Outcomes
		if request.GetApply() {
			if !bytes.Equal(digest, request.GetExpectedPlanSha256()) {
				response.FailureCode, response.FailureReason = "aborted", "organization_review_changed"
			} else {
				result, applyErr := orgapply.Apply(r.Context(), admin, plan, orgapply.Options{AccountClient: accounts})
				if result != nil {
					outcomes = result.Outcomes
					for _, secret := range result.Secrets {
						response.Secrets = append(response.Secrets, &orgv1.OrganizationSecret{Kind: secret.Kind, Name: secret.Name, Id: secret.ID, Secret: secret.Value, ExpiresAt: secret.ExpiresAt})
					}
				}
				if applyErr != nil {
					response.FailureCode, response.FailureReason = organizationFailureCode(applyErr), "organization_apply_incomplete"
				}
			}
		}
		for _, outcome := range outcomes {
			response.Outcomes = append(response.Outcomes, &orgv1.OrganizationOutcome{Kind: outcome.Kind, Name: outcome.Name, Id: outcome.ID, Status: outcome.Status, Detail: outcome.Detail})
		}
		writeOrganizationResponse(w, response)
	}))), nil
}

func organizationFailureCode(err error) string {
	switch {
	case errors.Is(err, identity.ErrAuthorizationDenied), errors.Is(err, identity.ErrAuthorizationChanged), errors.Is(err, identity.ErrAuthorizationExpired):
		return connect.CodePermissionDenied.String()
	case errors.Is(err, identity.ErrDirectoryUnavailable):
		return connect.CodeUnavailable.String()
	default:
		return connect.CodeOf(err).String()
	}
}

func writeOrganizationResponse(w http.ResponseWriter, response *orgv1.ApplyOrganizationResponse) {
	encoded, err := protojson.Marshal(response)
	if err != nil {
		http.Error(w, "Couldn't encode the organization result", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(encoded)
}
