// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/identity/identitydb"
)

// brokerLineage binds a verified broker token to an explicitly configured original
// directory. Neither imported broker attributes nor an email establish this proof.
type brokerLineage struct {
	BrokerIssuer     string
	BrokerSubject    string
	UpstreamProvider string
	UpstreamSubject  string
	Connector        string
}

func (l *brokerLineage) matches(row identitydb.PrincipalLineage) bool {
	return l != nil && l.BrokerIssuer == row.BrokerIssuer && l.BrokerSubject == row.BrokerSubject &&
		l.UpstreamProvider == row.UpstreamProvider && l.UpstreamSubject == row.UpstreamSubject && l.Connector == row.DirectoryConnector
}

// brokerSource polls BOTH directories on every observation. The upstream must be
// direct authority; broker enabled state and groups may only restrict its grants.
// It never stamps freshness: Service samples the database before either API read.
type brokerSource struct {
	pool           *pgxpool.Pool
	issuer         string
	upstreamIssuer string
	alias          string
	connector      string
	broker         *keycloakSource
	upstream       DirectorySource
}

var _ DirectorySource = (*brokerSource)(nil)

func newBrokerSource(ctx context.Context, pool *pgxpool.Pool, issuer string, cfg *configv1.KeycloakBrokerUpstream, secret string, broker *keycloakSource, client *http.Client, now func() time.Time) (*brokerSource, error) {
	if pool == nil || broker == nil || cfg == nil || cfg.GetAlias() == "" || cfg.GetConnectorId() == "" || cfg.GetIssuer() == issuer {
		return nil, errInvalidConfig
	}
	upstream, err := newKeycloakSource(ctx, cfg.GetIssuer(), cfg.GetDirectoryClientId(), secret, cfg.GetIssuer()+"/protocol/openid-connect/token", client, now)
	if err != nil {
		return nil, err
	}
	return &brokerSource{pool: pool, issuer: issuer, upstreamIssuer: cfg.GetIssuer(), alias: cfg.GetAlias(), connector: cfg.GetConnectorId(), broker: broker, upstream: upstream}, nil
}

func (s *Service) verifyBrokerClaims(_ context.Context, token *oidc.IDToken) (*brokerLineage, error) {
	if s.broker == nil {
		return nil, nil
	}
	var claims struct {
		Alias   string `json:"lindm_upstream_alias"`
		Subject string `json:"lindm_upstream_subject"`
	}
	if token == nil || token.Claims(&claims) != nil || claims.Alias != s.broker.alias {
		return nil, errUnauthenticated
	}
	lineage := &brokerLineage{BrokerIssuer: token.Issuer, BrokerSubject: token.Subject,
		UpstreamProvider: s.broker.upstreamIssuer, UpstreamSubject: claims.Subject, Connector: s.broker.connector}
	if !s.broker.qualified(lineage, token.Subject) {
		return nil, errUnauthenticated
	}
	return lineage, nil
}

func (s *brokerSource) qualified(lineage *brokerLineage, subject string) bool {
	if lineage == nil || lineage.BrokerIssuer != s.issuer || lineage.BrokerSubject != subject || s.upstreamIssuer == "" || lineage.UpstreamProvider != s.upstreamIssuer || lineage.Connector != s.connector {
		return false
	}
	// This connector is specifically Keycloak-to-Keycloak. UUID parsing belongs
	// here, not in the common DirectorySource contract or OIDC subject handling.
	brokerID, err := uuid.Parse(subject)
	if err != nil || brokerID == uuid.Nil || brokerID.String() != subject {
		return false
	}
	upstreamID, err := uuid.Parse(lineage.UpstreamSubject)
	return err == nil && upstreamID != uuid.Nil && upstreamID.String() == lineage.UpstreamSubject
}

func (s *brokerSource) Observe(ctx context.Context, subject string) (directoryObservation, error) {
	q := identitydb.New(s.pool)
	principal, err := q.GetPrincipalByIssuerSubject(ctx, identitydb.GetPrincipalByIssuerSubjectParams{Issuer: s.issuer, Subject: subject})
	if errors.Is(err, pgx.ErrNoRows) {
		return directoryObservation{}, ErrSubjectUnqualified
	}
	if err != nil {
		return directoryObservation{}, err
	}
	row, err := q.GetLineageByPrincipalID(ctx, principal.ID)
	if errors.Is(err, pgx.ErrNoRows) {
		return directoryObservation{}, ErrSubjectUnqualified
	}
	if err != nil {
		return directoryObservation{}, err
	}
	return s.ObserveLogin(ctx, subject, &brokerLineage{BrokerIssuer: row.BrokerIssuer, BrokerSubject: row.BrokerSubject,
		UpstreamProvider: row.UpstreamProvider, UpstreamSubject: row.UpstreamSubject, Connector: row.DirectoryConnector})
}

func (s *brokerSource) ObserveLogin(ctx context.Context, subject string, lineage *brokerLineage) (directoryObservation, error) {
	if !s.qualified(lineage, subject) {
		return directoryObservation{}, ErrSubjectUnqualified
	}
	id, err := uuid.Parse(subject)
	if err != nil {
		return directoryObservation{}, ErrSubjectUnqualified
	}
	body, status, err := s.broker.adminGet(ctx, "/users/"+url.PathEscape(subject))
	if err != nil {
		return directoryObservation{}, err
	}
	if status == http.StatusNotFound {
		return directoryObservation{}, nil
	}
	var user kcUser
	if status != http.StatusOK || json.Unmarshal(body, &user) != nil || user.ID != subject {
		return directoryObservation{}, errDirectoryResponse
	}
	obs := directoryObservation{Found: true, UserID: subject, DisplayName: directoryDisplayName(user.Username, user.FirstName, user.LastName), Lineage: lineage}
	links, err := s.broker.fetchFederated(ctx, id)
	if err != nil {
		return directoryObservation{}, err
	}
	if user.FederationLink != "" || len(links) != 1 || links[0].IdentityProvider != s.alias || links[0].UserID != lineage.UpstreamSubject {
		return obs, nil
	}
	// A healthy imported user must never mask an unavailable original directory,
	// even if its current local restrictions already deny access.
	upstream, err := s.upstream.Observe(ctx, lineage.UpstreamSubject)
	if err != nil {
		return directoryObservation{}, err
	}
	if !upstream.Found || !upstream.Direct || upstream.UserID != lineage.UpstreamSubject {
		return obs, nil
	}
	obs.Direct = true
	obs.Enabled = user.Enabled && upstream.Enabled
	if !obs.Enabled {
		return obs, nil
	}
	groups, err := s.broker.fetchGroups(ctx, id)
	if err != nil {
		return directoryObservation{}, err
	}
	allowed := make(map[string]struct{}, len(upstream.Groups))
	for _, group := range upstream.Groups {
		allowed[group] = struct{}{}
	}
	for _, group := range groups {
		if _, ok := allowed[group]; ok {
			obs.Groups = append(obs.Groups, group)
		}
	}
	return obs, nil
}
