// SPDX-License-Identifier: Apache-2.0

package webauthnlab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	authv1 "lindm/gen/lindm/auth/v1"
)

// RegisterSetupOwner exercises the real HTTP setup and UV registration boundary
// with a software lab authenticator. It is not physical authenticator or browser
// evidence; it lets business-domain fixtures avoid direct owner/bootstrap SQL.
func RegisterSetupOwner(ctx context.Context, handler http.Handler, origin, code, username, password string) (*authv1.SessionPrincipal, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return nil, errors.New("invalid lab setup origin")
	}
	authenticator, err := New(u.Hostname())
	if err != nil {
		return nil, err
	}
	post := func(path string, body proto.Message, result proto.Message, status int) ([]*http.Cookie, error) {
		encoded, err := protojson.Marshal(body)
		if err != nil {
			return nil, err
		}
		defer clear(encoded)
		request := httptest.NewRequest(http.MethodPost, origin+path, bytes.NewReader(encoded)).WithContext(ctx)
		request.Header.Set("Origin", origin)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-Lindm-Setup", "1")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != status {
			return nil, fmt.Errorf("lab owner setup %s: HTTP %d", path, recorder.Code)
		}
		if result != nil {
			if err = protojson.Unmarshal(recorder.Body.Bytes(), result); err != nil {
				return nil, err
			}
		}
		response := recorder.Result()
		cookies := response.Cookies()
		return cookies, response.Body.Close()
	}
	challenge := new(authv1.WebAuthnChallenge)
	if _, err := post("/auth/setup/begin", &authv1.FirstRunSetupRequest{Code: code, Username: username, Password: password}, challenge, http.StatusOK); err != nil {
		return nil, err
	}
	var options struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal([]byte(challenge.GetOptionsJson()), &options); err != nil || options.Challenge == "" {
		return nil, errors.New("invalid lab setup challenge")
	}
	credential, _, err := authenticator.Response(options.Challenge, origin, true, true, 0)
	if err != nil {
		return nil, err
	}
	defer clear(credential)
	cookies, err := post("/auth/local/enroll/finish", &authv1.WebAuthnFinishRequest{Token: challenge.GetToken(), CredentialJson: string(credential)}, nil, http.StatusNoContent)
	if err != nil {
		return nil, err
	}
	request := httptest.NewRequest(http.MethodGet, origin+"/auth/session", nil).WithContext(ctx)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		return nil, fmt.Errorf("lab owner setup session: HTTP %d", recorder.Code)
	}
	principal := new(authv1.SessionPrincipal)
	if err := protojson.Unmarshal(recorder.Body.Bytes(), principal); err != nil {
		return nil, err
	}
	if principal.GetId() == "" || principal.GetRole() != "owner" || principal.GetDisplayName() != username {
		return nil, errors.New("lab setup session does not identify its owner")
	}
	return principal, nil
}
