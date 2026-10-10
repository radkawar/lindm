package redhatimages

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const registrationOrigin = "https://console.redhat.com/api/rhsm/v2"
const registrationPrefix = "lindm-lab-"

// Registration owns one randomly named activation key. The guest consumer must
// be unregistered before Close deletes the key. Client must outlive Registration;
// neither supports concurrent calls. Credentials are never evidence or log data.
type Registration struct {
	client       *Client
	organization string
	key          string
	closed       bool
}

func (*Registration) String() string   { return "Red Hat registration lease (credentials redacted)" }
func (*Registration) GoString() string { return "Red Hat registration lease (credentials redacted)" }

// Credentials exposes the registration secrets only for private guest delivery.
// Do not put either value in process arguments, environment, diagnostics or logs.
func (r *Registration) Credentials() (organizationID, activationKey string) {
	if r.closed {
		return "", ""
	}
	return r.organization, r.key
}

// CreateRegistration creates only a uniquely named laboratory activation key.
// It does not mutate existing keys, subscriptions, terms, repository selections,
// or organization settings. An ambiguous create failure attempts bounded cleanup
// of this generated name; failures are returned, never hidden or retried.
func (c *Client) CreateRegistration(ctx context.Context) (*Registration, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	response, err := c.registrationRequest(ctx, http.MethodGet, "/organization", nil)
	if err != nil {
		return nil, err
	}
	var organization struct {
		Body struct {
			ID json.RawMessage `json:"id"`
		} `json:"body"`
	}
	decodeErr := decodeBounded(response.Body, &organization)
	closeErr := response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("redhatimages: organization read HTTP status %d", response.StatusCode)
	}
	if err := errors.Join(decodeErr, closeErr); err != nil {
		return nil, err
	}
	id := strings.Trim(string(organization.Body.ID), "\"")
	if _, err := strconv.ParseUint(id, 10, 64); err != nil || id == "" {
		return nil, errors.New("redhatimages: invalid organization identifier")
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, errors.New("redhatimages: generate activation-key identity failed")
	}
	lease := &Registration{client: c, organization: id, key: registrationPrefix + hex.EncodeToString(random[:])}
	// The only serialized registration credential is the HTTPS request body.
	payload, err := json.Marshal(struct {
		Name string `json:"name"`
	}{Name: lease.key})
	if err != nil {
		return nil, errors.New("redhatimages: encode activation-key request failed")
	}
	defer clear(payload)
	response, err = c.registrationRequest(ctx, http.MethodPost, "/activation_keys", bytes.NewReader(payload))
	if err != nil {
		return nil, errors.Join(err, lease.cleanupAfterFailure())
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		statusErr := fmt.Errorf("redhatimages: activation-key create HTTP status %d (rhc administrator permission required)", response.StatusCode)
		// Explicit rejection did not create our resource; a conflict must never
		// delete a key that existed before this request.
		if response.StatusCode >= 400 && response.StatusCode < 500 {
			return nil, statusErr
		}
		return nil, errors.Join(statusErr, lease.cleanupAfterFailure())
	}
	var created struct {
		Body struct {
			Name string `json:"name"`
		} `json:"body"`
	}
	if err := decodeBounded(response.Body, &created); err != nil {
		return nil, errors.Join(err, lease.cleanupAfterFailure())
	}
	if created.Body.Name != lease.key {
		return nil, errors.Join(errors.New("redhatimages: created activation-key identity mismatch"), lease.cleanupAfterFailure())
	}
	return lease, nil
}

func (r *Registration) cleanupAfterFailure() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	return r.Close(ctx)
}

// Close deletes only this lease's key. Call with an independent bounded cleanup
// context after unregistering the owned guest, even if its scenario was cancelled.
// A failed delete retains the lease so the caller can explicitly attempt cleanup.
func (r *Registration) Close(ctx context.Context) error {
	if r.closed {
		return nil
	}
	if err := r.client.deleteRegistration(ctx, r.key); err != nil {
		return err
	}
	r.closed = true
	r.organization, r.key = "", ""
	return nil
}

func ownedRegistration(name string) bool {
	if len(name) != len(registrationPrefix)+32 || !strings.HasPrefix(name, registrationPrefix) {
		return false
	}
	suffix := strings.TrimPrefix(name, registrationPrefix)
	decoded, err := hex.DecodeString(suffix)
	return err == nil && len(decoded) == 16 && strings.ToLower(suffix) == suffix
}

func (c *Client) deleteRegistration(ctx context.Context, name string) error {
	if !ownedRegistration(name) {
		return errors.New("redhatimages: refusing deletion outside the laboratory activation-key namespace")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	response, err := c.registrationRequest(ctx, http.MethodDelete, "/activation_keys/"+name, nil)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusNoContent && response.StatusCode != http.StatusNotFound {
		return fmt.Errorf("redhatimages: activation-key cleanup HTTP status %d", response.StatusCode)
	}
	return nil
}

// listRegistrations reads the complete unpaginated v2 activation-key list.
// Names remain private to the client and never appear in cleanup evidence.
func (c *Client) listRegistrations(ctx context.Context) ([]string, error) {
	response, err := c.registrationRequest(ctx, http.MethodGet, "/activation_keys", nil)
	if err != nil {
		return nil, err
	}
	var listed struct {
		Body []struct {
			Name string `json:"name"`
		} `json:"body"`
	}
	decodeErr := decodeBounded(response.Body, &listed)
	closeErr := response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("redhatimages: activation-key list HTTP status %d", response.StatusCode)
	}
	if err := errors.Join(decodeErr, closeErr); err != nil {
		return nil, err
	}
	if listed.Body == nil || len(listed.Body) > 1000 {
		return nil, errors.New("redhatimages: invalid activation-key list or exceeds 1000 entries")
	}
	var names []string
	seen := make(map[string]bool)
	for _, key := range listed.Body {
		if !ownedRegistration(key.Name) {
			continue
		}
		if seen[key.Name] {
			return nil, errors.New("redhatimages: duplicate activation-key list entry")
		}
		seen[key.Name] = true
		names = append(names, key.Name)
	}
	return names, nil
}

func (c *Client) registrationRequest(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	if path != "/organization" && path != "/activation_keys" && (!strings.HasPrefix(path, "/activation_keys/") || !ownedRegistration(strings.TrimPrefix(path, "/activation_keys/"))) {
		return nil, errors.New("redhatimages: refused registration API path")
	}
	if err := c.ensureBearer(ctx); err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, method, registrationOrigin+path, body)
	if err != nil {
		return nil, errors.New("redhatimages: construct registration API request failed")
	}
	request.Header.Set("Authorization", "Bearer "+c.bearer)
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(request)
	if err != nil {
		return nil, errors.New("redhatimages: registration HTTPS request failed")
	}
	return response, nil
}
