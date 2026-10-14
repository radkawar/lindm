// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"

	"google.golang.org/protobuf/proto"

	authv1 "lindm/gen/lindm/auth/v1"
	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/auditkind"
	"lindm/internal/identity/identitydb"
)

const scimCredentialDomain = "lindm.scim.connector.v1"

type scimCorrelation struct {
	issuer  string
	subject string
}

type scimConnector struct {
	digest       [sha256.Size]byte
	correlations map[string]scimCorrelation
}

type scimService struct {
	connectors map[string]scimConnector
}

// configureSCIM pins correlation before accepting provisioning. Persisted mappings
// cannot be reassigned, including after deletion. A configuration cutover revokes
// changed connector credentials and fences old replicas by their digest.
func (s *Service) configureSCIM(ctx context.Context, cfg *configv1.SCIMConfig) error {
	state := &scimService{connectors: make(map[string]scimConnector)}
	if cfg != nil {
		if err := s.rules.Validate(cfg); err != nil {
			return fmt.Errorf("identity: validate SCIM configuration: %w", err)
		}
		if s.localPrimary {
			return errors.New("identity: SCIM cannot manage local identities")
		}
		for _, connector := range cfg.GetConnectors() {
			encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(connector)
			if err != nil {
				return err
			}
			entry := scimConnector{digest: sha256.Sum256(encoded), correlations: make(map[string]scimCorrelation)}
			for _, correlation := range connector.GetCorrelations() {
				if correlation.GetIssuer() != s.issuer || correlation.GetIssuer() == s.localIssuer {
					return ErrIssuerMismatch
				}
				entry.correlations[correlation.GetProviderId()] = scimCorrelation{issuer: correlation.GetIssuer(), subject: correlation.GetSubject()}
			}
			state.connectors[connector.GetId()] = entry
		}
	}
	activeIDs := make([]string, 0, len(state.connectors))
	for id := range state.connectors {
		activeIDs = append(activeIDs, id)
	}
	err := s.withTx(ctx, func(q *identitydb.Queries) error {
		if err := q.LockSCIMConfiguration(ctx); err != nil {
			return s.dbErr(err)
		}
		if err := q.DisableSCIMConnectors(ctx, activeIDs); err != nil {
			return s.dbErr(err)
		}
		for id, connector := range state.connectors {
			if err := q.ConfigureSCIMConnector(ctx, identitydb.ConfigureSCIMConnectorParams{ID: id, ConfigDigest: connector.digest[:]}); err != nil {
				return s.dbErr(err)
			}
			for providerID, correlation := range connector.correlations {
				if err := q.InsertSCIMCorrelation(ctx, identitydb.InsertSCIMCorrelationParams{ConnectorID: id, ProviderID: providerID, Issuer: correlation.issuer, Subject: correlation.subject}); err != nil {
					return s.dbErr(err)
				}
				stored, err := q.GetSCIMCorrelation(ctx, identitydb.GetSCIMCorrelationParams{ConnectorID: id, ProviderID: providerID})
				if err != nil {
					return s.dbErr(err)
				}
				if stored.Issuer != correlation.issuer || stored.Subject != correlation.subject {
					return errors.New("identity: immutable SCIM correlation conflict")
				}
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.scim = state
	return nil
}

func (s *Service) registerSCIM(mux *http.ServeMux) {
	mux.HandleFunc("/scim/v2/", s.handleSCIM)
	mux.Handle("POST /auth/scim/credentials/rotate", s.RequireSession(http.HandlerFunc(s.handleRotateSCIMCredential)))
}

// RotateSCIMCredential provisions or replaces one dedicated connector bearer.
// The caller needs freshly fenced, unrestricted accounts.manage authority; a SCIM
// bearer itself cannot rotate credentials. Only the digest enters durable storage.
func (s *Service) RotateSCIMCredential(ctx context.Context, request *authv1.RotateSCIMCredentialRequest) (*authv1.SCIMCredential, error) {
	if err := s.rules.Validate(request); err != nil {
		return nil, err
	}
	if s.scim == nil {
		return nil, ErrAuthorizationDenied
	}
	configured, ok := s.scim.connectors[request.GetConnectorId()]
	if !ok {
		return nil, ErrAuthorizationDenied
	}
	secret, err := randomToken()
	if err != nil {
		return nil, err
	}
	actor, ok := PrincipalFromContext(ctx)
	unrestricted, _ := DeviceScopes(actor, PermissionManageAccounts)
	if !ok || !unrestricted {
		return nil, ErrAuthorizationDenied
	}
	authorization, err := s.AuthorizeFresh(ctx, actor.ID, PermissionManageAccounts)
	if err != nil {
		return nil, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, s.dbErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := identitydb.New(tx)
	// Match provisioning's connector-before-principal order. The credential
	// administrator can itself be the user being deactivated concurrently.
	connector, err := q.LockSCIMConnector(ctx, request.GetConnectorId())
	if err != nil {
		return nil, s.dbErr(err)
	}
	if !connector.Enabled || !bytes.Equal(connector.ConfigDigest, configured.digest[:]) {
		return nil, ErrAuthorizationDenied
	}
	if err := s.LockAuthorization(ctx, tx, authorization, PermissionManageAccounts); err != nil {
		return nil, err
	}
	if unrestricted, _ := DeviceScopes(authorization.Principal(), PermissionManageAccounts); !unrestricted {
		return nil, ErrAuthorizationDenied
	}
	if err := q.RotateSCIMCredential(ctx, identitydb.RotateSCIMCredentialParams{ID: connector.ID, CredentialHash: domainHash(scimCredentialDomain, secret)}); err != nil {
		return nil, s.dbErr(err)
	}
	if err := s.insertSystemAudit(ctx, q, &actor.ID, auditkind.IdentitySCIMCredentialRotated, "scim/"+connector.ID, "dedicated connector credential replaced"); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, s.dbErr(err)
	}
	return &authv1.SCIMCredential{ConnectorId: request.GetConnectorId(), BearerToken: secret}, nil
}

func (s *Service) handleRotateSCIMCredential(w http.ResponseWriter, r *http.Request) {
	request := &authv1.RotateSCIMCredentialRequest{}
	if !s.readAuthRequest(w, r, request) {
		return
	}
	response, err := s.RotateSCIMCredential(r.Context(), request)
	if err != nil {
		writeStatus(w, accountStatus(err))
		return
	}
	writeProto(w, response)
}
