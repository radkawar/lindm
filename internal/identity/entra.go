package identity

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// EntraIssuer returns the tenant-specific public-cloud v2 issuer. Common,
// organizations, consumer aliases and sovereign-cloud endpoints are not accepted.
func EntraIssuer(tenant string) (string, error) {
	id, err := uuid.Parse(tenant)
	if err != nil || id == uuid.Nil {
		return "", errInvalidConfig
	}
	return "https://login.microsoftonline.com/" + id.String() + "/v2.0", nil
}

// entraSource reads tenant-local account state and transitive Graph memberships.
// Its credentials never come from a browser access token. The tenant's objects,
// not a guest's home-directory lifecycle, are the authoritative boundary.
type entraSource struct {
	base       string
	httpClient *http.Client
	directory  *clientcredentials.Config
	now        func() time.Time
	// The context-aware gate serializes token acquisition and invalidation only;
	// Graph reads may proceed concurrently and never cache authority.
	tokenGate chan struct{}
	access    string
	expires   time.Time
}

var _ DirectorySource = (*entraSource)(nil)

func newEntraSource(ctx context.Context, base, clientID, secret, tokenURL string, client *http.Client, now func() time.Time) (*entraSource, error) {
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/v1.0" || clientID == "" || secret == "" || client == nil || now == nil || !strings.HasPrefix(tokenURL, "https://") {
		return nil, errInvalidConfig
	}
	boundedClient := *client
	boundedClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	s := &entraSource{
		base: base, httpClient: &boundedClient, now: now, tokenGate: make(chan struct{}, 1),
		directory: &clientcredentials.Config{
			ClientID: clientID, ClientSecret: secret, TokenURL: tokenURL,
			Scopes: []string{"https://graph.microsoft.com/.default"}, AuthStyle: oauth2.AuthStyleInParams,
		},
	}
	ctx, cancel := context.WithTimeout(ctx, directoryFetchTimeout)
	defer cancel()
	if _, err := s.directoryToken(ctx, ""); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *entraSource) Observe(ctx context.Context, subject string) (directoryObservation, error) {
	expected, err := uuid.Parse(subject)
	if err != nil || expected == uuid.Nil || expected.String() != subject {
		return directoryObservation{}, errDirectoryResponse
	}
	ctx, cancel := context.WithTimeout(ctx, directoryFetchTimeout)
	defer cancel()
	userURL := s.base + "/users/" + subject
	body, status, err := s.graphGet(ctx, userURL+"?$select=id,accountEnabled,displayName")
	if err != nil {
		return directoryObservation{}, err
	}
	if status == http.StatusNotFound {
		return directoryObservation{}, nil
	}
	if status != http.StatusOK {
		return directoryObservation{}, errDirectoryResponse
	}
	var user struct {
		ID             string `json:"id"`
		AccountEnabled *bool  `json:"accountEnabled"`
		DisplayName    string `json:"displayName"`
	}
	if err := json.Unmarshal(body, &user); err != nil || user.AccountEnabled == nil {
		return directoryObservation{}, errDirectoryResponse
	}
	id, err := uuid.Parse(user.ID)
	if err != nil || id != expected {
		return directoryObservation{}, errDirectoryResponse
	}
	obs := directoryObservation{Found: true, UserID: subject, Enabled: *user.AccountEnabled, Direct: true, DisplayName: sanitizeDisplay(user.DisplayName)}
	if !obs.Enabled {
		return obs, nil
	}
	groups, err := s.transitiveGroups(ctx, userURL+"/transitiveMemberOf/microsoft.graph.group")
	if err != nil {
		return directoryObservation{}, err
	}
	obs.Groups = groups
	return obs, nil
}

func (s *entraSource) transitiveGroups(ctx context.Context, collection string) ([]string, error) {
	next := collection + "?$select=id&$count=true&$top=" + strconv.Itoa(groupPageSize)
	var groups []string
	for range maxGroupPaths / groupPageSize {
		body, status, err := s.graphGet(ctx, next)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, errDirectoryResponse
		}
		var response struct {
			Value *[]struct {
				ID string `json:"id"`
			} `json:"value"`
			Next string `json:"@odata.nextLink"`
		}
		if err := json.Unmarshal(body, &response); err != nil || response.Value == nil || len(*response.Value) > groupPageSize || len(groups)+len(*response.Value) > maxGroupPaths {
			return nil, errDirectoryResponse
		}
		for _, group := range *response.Value {
			id, err := uuid.Parse(group.ID)
			if err != nil || id == uuid.Nil {
				return nil, errDirectoryResponse
			}
			groups = append(groups, id.String())
		}
		if response.Next == "" {
			return dedupeGroups(groups), nil
		}
		// Opaque Graph paging queries are followed only for this exact collection.
		// Never forward the app credential to another host, user or API path.
		u, err := url.Parse(response.Next)
		if err != nil || len(response.Next) > 8192 || u.User != nil || u.Fragment != "" || u.RawQuery == "" {
			return nil, errDirectoryResponse
		}
		u.RawQuery = ""
		if u.String() != collection || response.Next == next {
			return nil, errDirectoryResponse
		}
		next = response.Next
	}
	return nil, errDirectoryResponse
}

func (s *entraSource) directoryToken(ctx context.Context, rejected string) (string, error) {
	select {
	case s.tokenGate <- struct{}{}:
		defer func() { <-s.tokenGate }()
	case <-ctx.Done():
		return "", ErrDirectoryUnavailable
	}
	if rejected != "" && s.access == rejected {
		s.access = ""
	}
	if s.access != "" && s.now().Before(s.expires) {
		return s.access, nil
	}
	tok, err := s.directory.Token(context.WithValue(ctx, oauth2.HTTPClient, s.httpClient))
	if err != nil || tok == nil || tok.AccessToken == "" || !strings.EqualFold(tok.TokenType, "Bearer") || tok.Expiry.IsZero() {
		return "", ErrDirectoryUnavailable
	}
	s.access, s.expires = tok.AccessToken, tok.Expiry.Add(-30*time.Second)
	return s.access, nil
}

func (s *entraSource) graphGet(ctx context.Context, target string) ([]byte, int, error) {
	token, err := s.directoryToken(ctx, "")
	if err != nil {
		return nil, 0, err
	}
	refreshed := false
	for attempt := range 4 {
		body, status, retryAfter, err := s.graphGetOnce(ctx, target, token)
		if err != nil {
			return nil, status, err
		}
		switch status {
		case http.StatusUnauthorized:
			if refreshed {
				return nil, status, ErrDirectoryUnavailable
			}
			token, err = s.directoryToken(ctx, token)
			if err != nil {
				return nil, status, err
			}
			refreshed = true
		case http.StatusTooManyRequests, http.StatusServiceUnavailable:
			if attempt == 3 || waitGraphRetry(ctx, retryAfter, s.now()) != nil {
				return nil, status, ErrDirectoryUnavailable
			}
		default:
			return body, status, nil
		}
	}
	return nil, 0, ErrDirectoryUnavailable
}

func (s *entraSource) graphGetOnce(ctx context.Context, target, token string) (_ []byte, _ int, _ string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, 0, "", errDirectoryResponse
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	// Required by Graph for the group OData cast. Its propagation delay is a
	// separate live-qualification input, never an extension to snapshot lifetime.
	req.Header.Set("ConsistencyLevel", "eventual")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, 0, "", ErrDirectoryUnavailable
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			err = errors.Join(err, ErrDirectoryUnavailable)
		}
	}()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDirectoryBody+1))
	if err != nil || len(body) > maxDirectoryBody {
		return nil, resp.StatusCode, "", errDirectoryResponse
	}
	return body, resp.StatusCode, resp.Header.Get("Retry-After"), nil
}

func waitGraphRetry(ctx context.Context, header string, now time.Time) error {
	var delay time.Duration
	seconds, err := strconv.ParseUint(header, 10, 32)
	if err == nil {
		delay = time.Duration(seconds) * time.Second
	} else {
		at, err := http.ParseTime(header)
		if err != nil {
			return ErrDirectoryUnavailable
		}
		delay = max(0, at.Sub(now))
	}
	deadline, ok := ctx.Deadline()
	if !ok || delay >= time.Until(deadline) {
		return ErrDirectoryUnavailable
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ErrDirectoryUnavailable
	case <-timer.C:
		return nil
	}
}
