// SPDX-License-Identifier: Apache-2.0

package devlab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

type brokerRealmAdmin struct {
	client *http.Client
	realm  string
	secret string
	token  string
}

func (a *brokerRealmAdmin) authenticate(ctx context.Context) (resultErr error) {
	if a.realm != brokerRealm && a.realm != brokerUpstreamRealm {
		return errors.New("broker check refuses administration outside dedicated fixture realms")
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {"lindm-lab-admin"}, "client_secret": {a.secret}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://localhost:18443/realms/"+a.realm+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := a.client.Do(req)
	if err != nil {
		return errors.New("broker fixture lab-admin token request failed")
	}
	defer func() { resultErr = errors.Join(resultErr, resp.Body.Close()) }()
	body, err := readFixtureResponse(resp)
	if err != nil {
		return err
	}
	defer clear(body)
	var token struct {
		Access string `json:"access_token"`
		Type   string `json:"token_type"`
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &token) != nil || token.Access == "" || !strings.EqualFold(token.Type, "Bearer") {
		return fmt.Errorf("broker fixture lab-admin rejected in %s (HTTP %d); explicit fixture regeneration may be required", a.realm, resp.StatusCode)
	}
	a.token = token.Access
	return nil
}

func (a *brokerRealmAdmin) request(ctx context.Context, method, path string, payload any, want int) (header http.Header, body []byte, resultErr error) {
	if (a.realm != brokerRealm && a.realm != brokerUpstreamRealm) || !strings.HasPrefix(path, "/") || strings.Contains(path, "..") {
		return nil, nil, errors.New("invalid broker fixture request destination")
	}
	var reader io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, nil, err
		}
		defer clear(encoded)
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://localhost:18443/admin/realms/"+a.realm+path, reader)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, nil, errors.New("owned broker fixture request failed")
	}
	defer func() { resultErr = errors.Join(resultErr, resp.Body.Close()) }()
	if method == http.MethodDelete && resp.StatusCode == http.StatusNotFound {
		return resp.Header, nil, nil
	}
	if resp.StatusCode != want {
		return resp.Header, nil, fmt.Errorf("owned broker fixture %s %s in %s: HTTP %d, want %d", method, path, a.realm, resp.StatusCode, want)
	}
	body, err = readFixtureResponse(resp)
	return resp.Header, body, err
}

func (a *brokerRealmAdmin) create(ctx context.Context, resource string, payload any) (string, error) {
	header, _, err := a.request(ctx, http.MethodPost, "/"+resource, payload, http.StatusCreated)
	if err != nil {
		return "", err
	}
	location, err := url.Parse(header.Get("Location"))
	prefix := "/admin/realms/" + a.realm + "/" + resource + "/"
	if err != nil || location.Scheme != "https" || location.Host != "localhost:18443" || location.User != nil || location.RawQuery != "" || location.Fragment != "" || !strings.HasPrefix(location.Path, prefix) {
		return "", errors.New("owned broker fixture creation returned invalid location")
	}
	id := strings.TrimPrefix(location.Path, prefix)
	parsed, err := uuid.Parse(id)
	if err != nil || parsed == uuid.Nil || parsed.String() != id {
		return "", errors.New("invalid owned broker object ID")
	}
	return id, nil
}

func (a *brokerRealmAdmin) membership(ctx context.Context, user, group string, enabled bool) error {
	method := http.MethodDelete
	if enabled {
		method = http.MethodPut
	}
	_, _, err := a.request(ctx, method, "/users/"+user+"/groups/"+group, nil, http.StatusNoContent)
	return err
}

func brokerCleanupPrefix(prefix string) bool {
	id, err := uuid.Parse(strings.TrimPrefix(prefix, brokerOwnedPrefix))
	return strings.HasPrefix(prefix, brokerOwnedPrefix) && err == nil && id != uuid.Nil && brokerOwnedPrefix+id.String() == prefix
}

// cleanup resolves only this run's full random UUID prefix, also after a lost
// creation response. It never lists or deletes a shared lindm realm object.
func (a *brokerRealmAdmin) cleanup(ctx context.Context, prefix string, evidence io.Writer) error {
	if !brokerCleanupPrefix(prefix) {
		return errors.New("cleanup requires the complete lindm-broker-check-UUID prefix")
	}
	if err := a.authenticate(ctx); err != nil {
		return err
	}
	resources := []string{"users", "groups"}
	if a.realm == brokerRealm {
		resources = append(resources, "clients")
	}
	var result error
	for _, resource := range resources {
		query := url.Values{"search": {prefix}, "max": {"100"}, "briefRepresentation": {"false"}}
		if resource == "clients" {
			query = url.Values{"clientId": {prefix}, "max": {"100"}}
		}
		_, body, err := a.request(ctx, http.MethodGet, "/"+resource+"?"+query.Encode(), nil, http.StatusOK)
		if err != nil {
			result = errors.Join(result, err)
			continue
		}
		var objects []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Username string `json:"username"`
			ClientID string `json:"clientId"`
		}
		if json.Unmarshal(body, &objects) != nil || len(objects) >= 100 {
			result = errors.Join(result, errors.New("owned broker cleanup result exceeds bound"))
			continue
		}
		for _, object := range objects {
			name := object.Name
			if resource == "users" {
				name = object.Username
			}
			if resource == "clients" {
				name = object.ClientID
			}
			if name != prefix && !strings.HasPrefix(name, prefix+"-") {
				result = errors.Join(result, errors.New("broker cleanup refused unrelated search result"))
				continue
			}
			id, err := uuid.Parse(object.ID)
			if err != nil || id == uuid.Nil || id.String() != object.ID {
				result = errors.Join(result, errors.New("broker cleanup refused invalid object ID"))
				continue
			}
			_, _, err = a.request(ctx, http.MethodDelete, "/"+resource+"/"+object.ID, nil, http.StatusNoContent)
			if err == nil {
				_, err = fmt.Fprintf(evidence, "broker cleanup realm=%s %s=%s removed\n", a.realm, resource, object.ID)
			}
			result = errors.Join(result, err)
		}
	}
	return result
}

func brokerInputs(root string) (map[string]string, error) {
	dir := FixturePath(root)
	if err := validateAuthorityFixture(dir); err != nil {
		return nil, err
	}
	secrets := make(map[string]string, 4)
	for _, name := range []string{"broker-directory-secret", "broker-admin-secret", "broker-upstream-directory-secret", "broker-upstream-admin-secret"} {
		data, err := readOwned(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("broker fixture input %s unavailable; owner must explicitly regenerate maintained fixture: %w", name, err)
		}
		secrets[name] = strings.TrimSpace(string(data))
		clear(data)
		if secrets[name] == "" {
			return nil, errors.New("empty protected broker fixture credential")
		}
	}
	return secrets, nil
}

func cleanupBrokerOwned(ctx context.Context, admins []*brokerRealmAdmin, prefix string, evidence io.Writer) error {
	var result error
	for _, admin := range admins {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		result = errors.Join(result, admin.cleanup(cleanup, prefix, evidence))
		cancel()
	}
	return result
}
