// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"lindm/internal/identity/identitydb"
)

const (
	scimBase       = "/scim/v2/"
	scimCore       = "urn:ietf:params:scim:schemas:core:2.0:"
	scimMessages   = "urn:ietf:params:scim:api:messages:2.0:"
	scimMaxMembers = 1000
	scimMaxPage    = 100
	scimMaxBody    = 128 * 1024
)

type scimDocument map[string]any

type scimFailure struct {
	status int
	kind   string
	detail string
}

func (e *scimFailure) Error() string { return e.detail }

func scimError(status int, kind, detail string) error {
	return &scimFailure{status: status, kind: kind, detail: detail}
}

func writeSCIM(w http.ResponseWriter, status int, value any) {
	prepare(w)
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	if value != nil {
		_ = json.NewEncoder(w).Encode(value)
	}
}

func writeSCIMError(w http.ResponseWriter, err error) {
	failure := &scimFailure{status: http.StatusServiceUnavailable, detail: "Provisioning store unavailable"}
	var typed *scimFailure
	var database *pgconn.PgError
	switch {
	case errors.As(err, &typed):
		failure = typed
	case errors.Is(err, pgx.ErrNoRows):
		failure = &scimFailure{status: http.StatusNotFound, detail: "Resource not found"}
	case errors.As(err, &database) && database.Code == "23505":
		failure = &scimFailure{status: http.StatusConflict, kind: "uniqueness", detail: "Immutable identifier or userName already exists"}
	}
	if failure.status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="scim"`)
	}
	writeSCIM(w, failure.status, map[string]any{"schemas": []string{scimMessages + "Error"}, "status": strconv.Itoa(failure.status), "scimType": failure.kind, "detail": failure.detail})
}

func (s *Service) handleSCIM(w http.ResponseWriter, r *http.Request) {
	// This credential is never accepted by the login/session middleware. Cookies,
	// CLI bearers and multiple Authorization headers cannot provision resources.
	headers := r.Header.Values("Authorization")
	if s.scim == nil || len(headers) != 1 || len(headers[0]) != len("Bearer ")+43 || !strings.EqualFold(headers[0][:7], "Bearer ") {
		writeSCIMError(w, scimError(http.StatusUnauthorized, "", "Dedicated connector bearer required"))
		return
	}
	tx, err := s.pool.Begin(r.Context())
	if err != nil {
		writeSCIMError(w, err)
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	q := identitydb.New(tx)
	connector, err := q.AuthenticateSCIMConnector(r.Context(), domainHash(scimCredentialDomain, headers[0][7:]))
	if errors.Is(err, pgx.ErrNoRows) {
		err = scimError(http.StatusUnauthorized, "", "Invalid connector credential")
	}
	if err != nil {
		writeSCIMError(w, err)
		return
	}
	configured, ok := s.scim.connectors[connector.ID]
	if !ok || !bytes.Equal(connector.ConfigDigest, configured.digest[:]) {
		writeSCIMError(w, scimError(http.StatusUnauthorized, "", "Connector configuration changed"))
		return
	}
	status, result, etag, err := s.scimRequest(r, q, connector.ID, configured)
	if err != nil {
		writeSCIMError(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeSCIMError(w, err)
		return
	}
	if etag != "" {
		w.Header().Set("ETag", etag)
	}
	if document, ok := result.(scimDocument); ok {
		if meta, ok := document["meta"].(map[string]any); ok {
			if location, ok := meta["location"].(string); ok {
				w.Header().Set("Location", location)
			}
		}
	}
	writeSCIM(w, status, result)
}

func (s *Service) scimRequest(r *http.Request, q *identitydb.Queries, connectorID string, connector scimConnector) (int, any, string, error) {
	path := strings.TrimPrefix(r.URL.Path, scimBase)
	if value, ok := scimDiscovery(path); ok {
		if r.Method != http.MethodGet {
			return 0, nil, "", scimError(http.StatusMethodNotAllowed, "", "Discovery is read-only")
		}
		return http.StatusOK, value, "", nil
	}
	parts := strings.Split(path, "/")
	if len(parts) > 2 || (parts[0] != "Users" && parts[0] != "Groups") {
		return 0, nil, "", scimError(http.StatusNotFound, "", "Unknown SCIM resource")
	}
	kind := strings.TrimSuffix(parts[0], "s")
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			result, err := s.listSCIM(r, q, connectorID, kind)
			return http.StatusOK, result, "", err
		case http.MethodPost:
			doc, err := readSCIMDocument(r)
			if err != nil {
				return 0, nil, "", err
			}
			row, err := s.createSCIM(r.Context(), q, connectorID, connector, kind, doc)
			if err != nil {
				return 0, nil, "", err
			}
			result, err := s.renderSCIM(r.Context(), q, row)
			return http.StatusCreated, result, scimETag(row.Version), err
		default:
			return 0, nil, "", scimError(http.StatusMethodNotAllowed, "", "Unsupported collection method")
		}
	}
	id, err := uuid.Parse(parts[1])
	if err != nil {
		return 0, nil, "", scimError(http.StatusNotFound, "", "Resource not found")
	}
	row, err := q.GetSCIMResource(r.Context(), identitydb.GetSCIMResourceParams{ConnectorID: connectorID, ResourceType: kind, ID: id})
	if err != nil {
		return 0, nil, "", err
	}
	if row.Deleted {
		return 0, nil, "", scimError(http.StatusNotFound, "", "Resource deleted")
	}
	if r.Method == http.MethodGet {
		result, err := s.renderSCIM(r.Context(), q, row)
		return http.StatusOK, result, scimETag(row.Version), err
	}
	if r.Method != http.MethodPut && r.Method != http.MethodPatch && r.Method != http.MethodDelete {
		return 0, nil, "", scimError(http.StatusMethodNotAllowed, "", "Unsupported resource method")
	}
	if r.Header.Get("If-Match") == "" {
		return 0, nil, "", scimError(http.StatusPreconditionRequired, "", "If-Match resource version required")
	}
	if r.Header.Get("If-Match") != scimETag(row.Version) {
		return 0, nil, "", scimError(http.StatusPreconditionFailed, "", "Resource version changed")
	}
	doc, err := s.renderSCIM(r.Context(), q, row)
	if err != nil {
		return 0, nil, "", err
	}
	switch r.Method {
	case http.MethodPut:
		doc, err = readSCIMDocument(r)
	case http.MethodPatch:
		err = patchSCIM(r, doc)
	}
	if err != nil {
		return 0, nil, "", err
	}
	row, err = s.updateSCIM(r.Context(), q, connector, row, doc, r.Method == http.MethodDelete)
	if err != nil {
		return 0, nil, "", err
	}
	if row.Deleted {
		return http.StatusNoContent, nil, "", nil
	}
	result, err := s.renderSCIM(r.Context(), q, row)
	return http.StatusOK, result, scimETag(row.Version), err
}

func readSCIMDocument(r *http.Request) (scimDocument, error) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || (media != "application/scim+json" && media != "application/json") {
		return nil, scimError(http.StatusUnsupportedMediaType, "", "SCIM JSON required")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, scimMaxBody+1))
	if err != nil {
		return nil, scimError(http.StatusBadRequest, "invalidSyntax", "Cannot read SCIM body")
	}
	if len(body) > scimMaxBody {
		return nil, scimError(http.StatusRequestEntityTooLarge, "", "SCIM body exceeds limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var document scimDocument
	if err := decoder.Decode(&document); err != nil || document == nil {
		return nil, scimError(http.StatusBadRequest, "invalidSyntax", "Invalid JSON object")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, scimError(http.StatusBadRequest, "invalidSyntax", "Multiple JSON values or oversized body")
	}
	return document, nil
}

func scimETag(version int64) string { return `W/"` + strconv.FormatInt(version, 10) + `"` }

func (s *Service) listSCIM(r *http.Request, q *identitydb.Queries, connectorID, kind string) (any, error) {
	query := r.URL.Query()
	for key := range query {
		if key != "filter" && key != "startIndex" && key != "count" {
			return nil, scimError(http.StatusBadRequest, "invalidValue", "Unsupported query parameter")
		}
	}
	start, count := 1, scimMaxPage
	var err error
	if value := query.Get("startIndex"); value != "" {
		start, err = strconv.Atoi(value)
		if err != nil || start < 1 || start > 1000001 {
			return nil, scimError(http.StatusBadRequest, "invalidValue", "startIndex outside bounded range")
		}
	}
	if value := query.Get("count"); value != "" {
		count, err = strconv.Atoi(value)
		if err != nil || count < 0 {
			return nil, scimError(http.StatusBadRequest, "invalidValue", "Invalid count")
		}
		count = min(count, scimMaxPage)
	}
	attribute, value, err := scimFilter(query.Get("filter"))
	if err != nil {
		return nil, err
	}
	if kind == "Group" && attribute == "userName" {
		return nil, scimError(http.StatusBadRequest, "invalidFilter", "Groups do not have userName")
	}
	total, err := q.CountSCIMResources(r.Context(), identitydb.CountSCIMResourcesParams{ConnectorID: connectorID, ResourceType: kind, FilterAttribute: attribute, FilterValue: value})
	if err != nil {
		return nil, err
	}
	rows, err := q.ListSCIMResources(r.Context(), identitydb.ListSCIMResourcesParams{ConnectorID: connectorID, ResourceType: kind, FilterAttribute: attribute, FilterValue: value, PageLimit: int32(count), PageOffset: int32(start - 1)})
	if err != nil {
		return nil, err
	}
	resources := make([]scimDocument, 0, len(rows))
	for _, row := range rows {
		doc, err := s.renderSCIM(r.Context(), q, row)
		if err != nil {
			return nil, err
		}
		resources = append(resources, doc)
	}
	return map[string]any{"schemas": []string{scimMessages + "ListResponse"}, "totalResults": total, "startIndex": start, "itemsPerPage": len(resources), "Resources": resources}, nil
}

func scimFilter(filter string) (string, string, error) {
	if filter == "" {
		return "", "", nil
	}
	parts := strings.SplitN(strings.TrimSpace(filter), " ", 3)
	if len(parts) != 3 || !strings.EqualFold(parts[1], "eq") {
		return "", "", scimError(http.StatusBadRequest, "invalidFilter", "Only userName/externalId eq filters are supported")
	}
	attribute := ""
	for _, name := range []string{"userName", "externalId"} {
		if strings.EqualFold(parts[0], name) {
			attribute = name
		}
	}
	var value string
	if attribute == "" || json.Unmarshal([]byte(parts[2]), &value) != nil || !boundedText(value, 0, 256) {
		return "", "", scimError(http.StatusBadRequest, "invalidFilter", "Invalid equality filter")
	}
	return attribute, value, nil
}
