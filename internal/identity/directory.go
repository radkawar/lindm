package identity

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// keycloakSource reads only the configured realm's authoritative Admin API.
// Brokered and federated identities do not qualify as direct authority.
type keycloakSource struct {
	adminBase  string
	httpClient *http.Client
	directory  *clientcredentials.Config
	tokens     tokenCache
	flights    flightGroup
	now        func() time.Time
}

var _ DirectorySource = (*keycloakSource)(nil)

type tokenCache struct {
	mu      sync.Mutex
	access  string
	expires time.Time
}

func newKeycloakSource(ctx context.Context, issuer, clientID, clientSecret, tokenURL string, httpClient *http.Client, now func() time.Time) (*keycloakSource, error) {
	if clientID == "" || clientSecret == "" || httpClient == nil || now == nil || !strings.HasPrefix(tokenURL, "https://") {
		return nil, errInvalidConfig
	}
	adminBase, err := adminRealmBase(issuer)
	if err != nil {
		return nil, err
	}
	source := &keycloakSource{
		adminBase:  adminBase,
		httpClient: httpClient,
		directory: &clientcredentials.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			TokenURL:     tokenURL,
			AuthStyle:    oauth2.AuthStyleInParams,
		},
		now: now,
	}
	if _, err := source.directoryToken(ctx); err != nil {
		return nil, err
	}
	return source, nil
}

type kcUser struct {
	ID             string `json:"id"`
	Username       string `json:"username"`
	Enabled        bool   `json:"enabled"`
	FirstName      string `json:"firstName"`
	LastName       string `json:"lastName"`
	FederationLink string `json:"federationLink"`
}

type kcGroup struct {
	Path string `json:"path"`
}

type kcFederated struct {
	IdentityProvider string `json:"identityProvider"`
	UserID           string `json:"userId"`
}

func (s *keycloakSource) Observe(ctx context.Context, subject string) (directoryObservation, error) {
	expected, err := uuid.Parse(subject)
	if err != nil || expected == uuid.Nil || expected.String() != subject {
		return directoryObservation{}, errDirectoryResponse
	}
	body, status, err := s.adminGet(ctx, "/users/"+url.PathEscape(subject))
	if err != nil {
		return directoryObservation{}, err
	}
	if status == http.StatusNotFound {
		return directoryObservation{}, nil
	}
	if status != http.StatusOK {
		return directoryObservation{}, errDirectoryResponse
	}
	var user kcUser
	if err := json.Unmarshal(body, &user); err != nil {
		return directoryObservation{}, errDirectoryResponse
	}
	id, err := uuid.Parse(user.ID)
	if err != nil || id != expected {
		return directoryObservation{}, errDirectoryResponse
	}
	obs := directoryObservation{
		Found:       true,
		UserID:      subject,
		DisplayName: directoryDisplayName(user.Username, user.FirstName, user.LastName),
		Enabled:     user.Enabled,
		Direct:      user.FederationLink == "",
	}
	if !obs.Enabled {
		return obs, nil
	}
	federated, err := s.fetchFederated(ctx, id)
	if err != nil {
		return directoryObservation{}, err
	}
	if user.FederationLink != "" || len(federated) > 0 {
		obs.Direct = false
		obs.Groups = nil
		return obs, nil
	}
	groups, err := s.fetchGroups(ctx, id)
	if err != nil {
		return directoryObservation{}, err
	}
	obs.Groups = groups
	obs.Direct = true
	return obs, nil
}

func (s *keycloakSource) fetchFederated(ctx context.Context, id uuid.UUID) ([]kcFederated, error) {
	body, status, err := s.adminGet(ctx, "/users/"+url.PathEscape(id.String())+"/federated-identity")
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, errDirectoryResponse
	}
	var links []kcFederated
	if err := json.Unmarshal(body, &links); err != nil {
		return nil, errDirectoryResponse
	}
	return links, nil
}

func (s *keycloakSource) fetchGroups(ctx context.Context, id uuid.UUID) ([]string, error) {
	var out []string
	for first := 0; first < maxGroupPaths; first += groupPageSize {
		q := url.Values{}
		q.Set("briefRepresentation", "false")
		q.Set("first", strconv.Itoa(first))
		q.Set("max", strconv.Itoa(groupPageSize))
		path := "/users/" + url.PathEscape(id.String()) + "/groups?" + q.Encode()
		body, status, err := s.adminGet(ctx, path)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, errDirectoryResponse
		}
		var page []kcGroup
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, errDirectoryResponse
		}
		for _, g := range page {
			if !validGroupPath(g.Path) {
				return nil, errDirectoryResponse
			}
			out = append(out, g.Path)
		}
		if len(page) < groupPageSize {
			return dedupeGroups(out), nil
		}
	}
	return nil, errDirectoryResponse
}

func (s *keycloakSource) adminGet(ctx context.Context, path string) ([]byte, int, error) {
	body, status, err := s.adminGetOnce(ctx, path)
	if err == nil && status == http.StatusUnauthorized {
		s.clearDirectoryToken()
		return s.adminGetOnce(ctx, path)
	}
	return body, status, err
}

func (s *keycloakSource) adminGetOnce(ctx context.Context, path string) (_ []byte, _ int, err error) {
	if !strings.HasPrefix(path, "/") || strings.Contains(path, "://") || strings.Contains(path, "..") {
		return nil, 0, errDirectoryResponse
	}
	token, err := s.directoryToken(ctx)
	if err != nil {
		return nil, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.adminBase+path, nil)
	if err != nil {
		return nil, 0, errDirectoryResponse
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, 0, directoryUnavailable(ctx)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			err = errors.Join(err, ErrDirectoryUnavailable)
		}
	}()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDirectoryBody+1))
	if ctx.Err() != nil {
		return nil, 0, directoryUnavailable(ctx)
	}
	if err != nil {
		return nil, resp.StatusCode, errDirectoryResponse
	}
	if len(body) > maxDirectoryBody {
		return nil, resp.StatusCode, errDirectoryResponse
	}
	return body, resp.StatusCode, nil
}

func (s *keycloakSource) directoryToken(ctx context.Context) (string, error) {
	if access, ok := s.cachedAccess(s.now()); ok {
		return access, nil
	}
	v, err := s.flights.Do("directory-token", func() (any, error) {
		if access, ok := s.cachedAccess(s.now()); ok {
			return access, nil
		}
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), directoryFetchTimeout)
		defer cancel()
		fctx = context.WithValue(fctx, oauth2.HTTPClient, s.httpClient)
		tok, err := s.directory.Token(fctx)
		if err != nil || tok == nil || tok.AccessToken == "" {
			slog.Warn("identity directory token request failed")
			return "", ErrDirectoryUnavailable
		}
		expires := tok.Expiry
		if expires.IsZero() {
			expires = s.now().Add(time.Minute)
		} else {
			expires = expires.Add(-30 * time.Second)
		}
		s.tokens.mu.Lock()
		s.tokens.access = tok.AccessToken
		s.tokens.expires = expires
		s.tokens.mu.Unlock()
		return tok.AccessToken, nil
	})
	if err != nil {
		return "", err
	}
	access, _ := v.(string)
	if access == "" {
		return "", ErrDirectoryUnavailable
	}
	return access, nil
}

func (s *keycloakSource) cachedAccess(now time.Time) (string, bool) {
	s.tokens.mu.Lock()
	defer s.tokens.mu.Unlock()
	if s.tokens.access == "" || !now.Before(s.tokens.expires) {
		return "", false
	}
	return s.tokens.access, true
}

func (s *keycloakSource) clearDirectoryToken() {
	s.tokens.mu.Lock()
	s.tokens.access = ""
	s.tokens.expires = time.Time{}
	s.tokens.mu.Unlock()
}

func directoryDisplayName(username, first, last string) string {
	name := strings.TrimSpace(strings.TrimSpace(first) + " " + strings.TrimSpace(last))
	if name == "" {
		name = strings.TrimSpace(username)
	}
	return sanitizeDisplay(name)
}

func sanitizeDisplay(s string) string {
	if !utf8.ValidString(s) {
		return ""
	}
	var b strings.Builder
	n := 0
	for _, r := range s {
		if r == 0 || unicode.IsControl(r) {
			continue
		}
		if n == 256 {
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

func validGroupPath(path string) bool {
	return path != "" && utf8.ValidString(path) && utf8.RuneCountInString(path) <= 512 && !strings.ContainsAny(path, "\x00\r\n")
}

func dedupeGroups(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, g := range in {
		if _, ok := seen[g]; ok {
			continue
		}
		seen[g] = struct{}{}
		out = append(out, g)
	}
	return out
}

func adminRealmBase(issuer string) (string, error) {
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errInvalidConfig
	}
	if strings.HasSuffix(u.Path, "/") {
		return "", errInvalidConfig
	}
	const marker = "/realms/"
	i := strings.LastIndex(u.Path, marker)
	if i < 0 {
		return "", errInvalidConfig
	}
	realm := u.Path[i+len(marker):]
	if !validRealm(realm) {
		return "", errInvalidConfig
	}
	base := *u
	base.Path = u.Path[:i] + "/admin/realms/" + realm
	base.RawPath = ""
	base.RawQuery = ""
	base.Fragment = ""
	return base.String(), nil
}

func validRealm(realm string) bool {
	if realm == "" || len(realm) > 128 {
		return false
	}
	for _, r := range realm {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return true
}
