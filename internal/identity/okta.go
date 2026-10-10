package identity

import (
	"context"
	"encoding/json"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
)

// oktaSource always uses the org Management API and org authorization server,
// including when browser login uses a custom authorization server. Only ACTIVE
// accounts qualify; profile names, login aliases and token group claims do not.
type oktaSource struct {
	base  string
	oauth *providerOAuth
}

var _ DirectorySource = (*oktaSource)(nil)

func newOktaSource(ctx context.Context, orgURL, clientID, keyID string, privateKeyPEM []byte, client *http.Client, now func() time.Time) (*oktaSource, error) {
	u, err := url.Parse(orgURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") || clientID == "" {
		return nil, errInvalidConfig
	}
	p, err := newProviderOAuth(client, now)
	if err != nil {
		return nil, err
	}
	signer, err := providerSigner(privateKeyPEM, keyID)
	if err != nil {
		return nil, err
	}
	origin := strings.TrimSuffix(orgURL, "/")
	p.tokenURL = origin + "/oauth2/v1/token"
	p.retry = oktaRetry
	p.form = func() (url.Values, error) {
		issued := now()
		assertion, err := jwt.Signed(signer).Claims(jwt.Claims{
			Issuer: clientID, Subject: clientID, Audience: jwt.Audience{p.tokenURL},
			IssuedAt: jwt.NewNumericDate(issued), Expiry: jwt.NewNumericDate(issued.Add(5 * time.Minute)), ID: uuid.NewString(),
		}).Serialize()
		if err != nil {
			return nil, err
		}
		return url.Values{
			"grant_type": {"client_credentials"}, "scope": {"okta.users.read okta.groups.read"},
			"client_id": {clientID}, "client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
			"client_assertion": {assertion},
		}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, directoryFetchTimeout)
	defer cancel()
	if _, err := p.token(ctx, ""); err != nil {
		return nil, err
	}
	return &oktaSource{base: origin + "/api/v1", oauth: p}, nil
}

func (s *oktaSource) Observe(ctx context.Context, subject string) (directoryObservation, error) {
	if !providerObjectID(subject) {
		return directoryObservation{}, errDirectoryResponse
	}
	ctx, cancel := context.WithTimeout(ctx, directoryFetchTimeout)
	defer cancel()
	userURL := s.base + "/users/" + subject
	body, status, _, err := s.oauth.get(ctx, userURL)
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
		ID      string `json:"id"`
		Status  string `json:"status"`
		Profile struct {
			FirstName string `json:"firstName"`
			LastName  string `json:"lastName"`
		} `json:"profile"`
	}
	if json.Unmarshal(body, &user) != nil || user.ID != subject || user.Status == "" {
		return directoryObservation{}, errDirectoryResponse
	}
	obs := directoryObservation{Found: true, UserID: subject, Direct: true, Enabled: user.Status == "ACTIVE", DisplayName: sanitizeDisplay(strings.TrimSpace(user.Profile.FirstName + " " + user.Profile.LastName))}
	if !obs.Enabled {
		return obs, nil
	}
	obs.Groups, err = s.groups(ctx, userURL+"/groups")
	if err != nil {
		return directoryObservation{}, err
	}
	return obs, nil
}

func (s *oktaSource) groups(ctx context.Context, collection string) ([]string, error) {
	next := collection + "?limit=" + strconv.Itoa(groupPageSize)
	seen := make(map[string]bool)
	var groups []string
	for range maxGroupPaths / groupPageSize {
		if seen[next] {
			return nil, errDirectoryResponse
		}
		seen[next] = true
		body, status, header, err := s.oauth.get(ctx, next)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, errDirectoryResponse
		}
		var page []struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(body, &page) != nil || page == nil || len(groups)+len(page) > maxGroupPaths {
			return nil, errDirectoryResponse
		}
		for _, group := range page {
			if !providerObjectID(group.ID) {
				return nil, errDirectoryResponse
			}
			groups = append(groups, group.ID)
		}
		next, err = oktaNextLink(header.Values("Link"), collection)
		if err != nil {
			return nil, err
		}
		if next == "" {
			return dedupeGroups(groups), nil
		}
	}
	return nil, errDirectoryResponse
}

// Okta emits absolute Link targets. Accept only this exact collection, even on
// the same origin: never let pagination send credentials to another API/user.
func oktaNextLink(headers []string, collection string) (string, error) {
	var next string
	for _, header := range headers {
		if len(header) > 8192 {
			return "", errDirectoryResponse
		}
		for _, link := range strings.Split(header, ",") {
			link = strings.TrimSpace(link)
			end := strings.IndexByte(link, '>')
			if !strings.HasPrefix(link, "<") || end < 2 {
				return "", errDirectoryResponse
			}
			_, params, err := mime.ParseMediaType("application/link" + link[end+1:])
			if err != nil {
				return "", errDirectoryResponse
			}
			isNext := false
			for _, rel := range strings.Fields(params["rel"]) {
				isNext = isNext || rel == "next"
			}
			if !isNext {
				continue
			}
			target := link[1:end]
			u, err := url.Parse(target)
			if err != nil || u.User != nil || u.Fragment != "" || u.RawQuery == "" || next != "" {
				return "", errDirectoryResponse
			}
			u.RawQuery = ""
			if u.String() != collection {
				return "", errDirectoryResponse
			}
			next = target
		}
	}
	return next, nil
}

func oktaRetry(status int, header http.Header, _ []byte, _ int, now time.Time) (time.Duration, bool, error) {
	if status != http.StatusTooManyRequests && status != http.StatusServiceUnavailable {
		return 0, false, nil
	}
	var delay time.Duration
	present := false
	if value := header.Get("Retry-After"); value != "" {
		var err error
		delay, err = providerRetryAfter(value, now)
		if err != nil {
			return 0, false, err
		}
		present = true
	}
	if value := header.Get("X-Rate-Limit-Reset"); value != "" {
		seconds, err := strconv.ParseInt(value, 10, 64)
		if err != nil || seconds < 0 || seconds > now.Add(directoryFetchTimeout).Unix() {
			return 0, false, ErrDirectoryUnavailable
		}
		delay = max(delay, time.Unix(seconds, 0).Sub(now))
		present = true
	}
	if !present {
		return 0, false, ErrDirectoryUnavailable
	}
	return delay, true, nil
}
