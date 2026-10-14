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
	"strings"
	"time"

	"github.com/google/uuid"
)

const freshAdminBase = "https://localhost:18443/admin/realms/lindm"

// This adapter can mutate only the two randomly named objects created by one
// check. It never configures the realm or lends lab-admin authority to identity.
type freshDirectoryFixture struct {
	client       *http.Client
	secret       string
	token        string
	name         string
	userID       string
	groupID      string
	pendingUser  bool
	pendingGroup bool
}

func (f *freshDirectoryFixture) authenticate(ctx context.Context) (err error) {
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {"lindm-lab-admin"}, "client_secret": {f.secret}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, issuer+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		return errors.New("construct fresh-check lab-admin token request failed")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := f.client.Do(req)
	if err != nil {
		return errors.New("fresh-check lab-admin token request failed")
	}
	defer func() { err = errors.Join(err, resp.Body.Close()) }()
	body, err := readFixtureResponse(resp)
	if err != nil {
		return err
	}
	defer clear(body)
	var token struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &token) != nil || token.AccessToken == "" || !strings.EqualFold(token.TokenType, "Bearer") {
		return fmt.Errorf("fresh-check lab-admin token rejected (HTTP %d)", resp.StatusCode)
	}
	f.token = token.AccessToken
	return nil
}

func (f *freshDirectoryFixture) request(ctx context.Context, method, path string, payload any, status int) (header http.Header, data []byte, err error) {
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, nil, errors.New("encode owned Keycloak fixture request failed")
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, freshAdminBase+path, body)
	if err != nil {
		return nil, nil, errors.New("construct owned Keycloak fixture request failed")
	}
	req.Header.Set("Authorization", "Bearer "+f.token)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("owned Keycloak fixture %s %s failed", method, path)
	}
	defer func() { err = errors.Join(err, resp.Body.Close()) }()
	if resp.StatusCode != status {
		return resp.Header, nil, fmt.Errorf("owned Keycloak fixture %s %s: HTTP %d, want %d", method, path, resp.StatusCode, status)
	}
	if status == http.StatusCreated || status == http.StatusNoContent {
		return resp.Header, nil, nil
	}
	data, err = readFixtureResponse(resp)
	return resp.Header, data, err
}

func freshOwnedID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value &&
		value != ownerSubject && value != "00000000-0000-4000-8000-000000000002" && value != "00000000-0000-4000-8000-000000000100"
}

func (f *freshDirectoryFixture) create(ctx context.Context, resource string) (string, error) {
	var payload any = map[string]any{"name": f.name}
	pending := &f.pendingGroup
	if resource == "users" {
		payload = map[string]any{
			"username": f.name, "enabled": true, "email": f.name + "@lindm.example",
			"firstName": "Fresh", "lastName": "Initial",
		}
		pending = &f.pendingUser
	}
	// A lost response may follow a committed creation. Cleanup resolves only the
	// exact random name from this attempt, never a broad prefix deletion.
	*pending = true
	header, _, err := f.request(ctx, http.MethodPost, "/"+resource, payload, http.StatusCreated)
	if err != nil {
		if header != nil {
			// A definite rejected request did not create an owned object.
			*pending = false
		}
		return "", err
	}
	location, err := url.Parse(header.Get("Location"))
	prefix := "/admin/realms/lindm/" + resource + "/"
	if err != nil || location.Scheme != "https" || location.Host != "localhost:18443" || location.User != nil || location.RawQuery != "" || location.Fragment != "" || !strings.HasPrefix(location.Path, prefix) {
		return "", errors.New("owned Keycloak creation returned an invalid location")
	}
	id := strings.TrimPrefix(location.Path, prefix)
	if !freshOwnedID(id) {
		return "", errors.New("owned Keycloak creation returned an invalid object ID")
	}
	return id, nil
}

func (f *freshDirectoryFixture) membership(ctx context.Context, member bool) error {
	method := http.MethodDelete
	if member {
		method = http.MethodPut
	}
	_, _, err := f.request(ctx, method, "/users/"+f.userID+"/groups/"+f.groupID, nil, http.StatusNoContent)
	return err
}

func (f *freshDirectoryFixture) updateUser(ctx context.Context, changes map[string]any) error {
	_, _, err := f.request(ctx, http.MethodPut, "/users/"+f.userID, changes, http.StatusNoContent)
	return err
}

func (f *freshDirectoryFixture) recoverID(ctx context.Context, resource string) (string, error) {
	query := url.Values{"exact": {"true"}, "max": {"2"}, "briefRepresentation": {"false"}}
	if resource == "users" {
		query.Set("username", f.name)
	} else {
		query.Set("search", f.name)
	}
	_, body, err := f.request(ctx, http.MethodGet, "/"+resource+"?"+query.Encode(), nil, http.StatusOK)
	if err != nil {
		return "", err
	}
	var objects []struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Username string `json:"username"`
	}
	if json.Unmarshal(body, &objects) != nil || len(objects) > 1 {
		return "", errors.New("owned Keycloak cleanup lookup was invalid or ambiguous")
	}
	if len(objects) == 0 {
		return "", nil
	}
	object := objects[0]
	name := object.Name
	if resource == "users" {
		name = object.Username
	}
	if name != f.name || !freshOwnedID(object.ID) {
		return "", fmt.Errorf("refusing cleanup of unverified Keycloak %s object", resource)
	}
	return object.ID, nil
}

func (f *freshDirectoryFixture) close(ctx context.Context, evidence io.Writer) error {
	if !f.pendingUser && !f.pendingGroup {
		return nil
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	err := f.authenticate(cleanup)
	cancel()
	if err != nil {
		return fmt.Errorf("cleanup owned Keycloak objects name=%s user=%s group=%s: %w", f.name, f.userID, f.groupID, err)
	}
	var result error
	// Deleting the owned user precedes deleting its owned group, even on failure.
	for _, object := range []struct {
		resource string
		id       *string
		pending  bool
	}{{"users", &f.userID, f.pendingUser}, {"groups", &f.groupID, f.pendingGroup}} {
		if !object.pending {
			continue
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		if *object.id == "" {
			*object.id, err = f.recoverID(cleanup, object.resource)
		} else {
			err = nil
		}
		if err == nil && *object.id != "" {
			_, _, err = f.request(cleanup, http.MethodDelete, "/"+object.resource+"/"+*object.id, nil, http.StatusNoContent)
		}
		cancel()
		if err != nil {
			result = errors.Join(result, fmt.Errorf("cleanup owned Keycloak %s id=%s name=%s: %w", object.resource, *object.id, f.name, err))
			continue
		}
		_, err = fmt.Fprintf(evidence, "fresh-authorization cleanup %s=%s removed\n", object.resource, *object.id)
		result = errors.Join(result, err)
	}
	return result
}
