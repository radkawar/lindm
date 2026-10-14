// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"encoding/json"
	"math/rand/v2"
	"net/http"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
)

// googleSource checks configured immutable group IDs with members.hasMember.
// Google includes direct and nested membership within the same domain; nested
// cross-domain membership can return Invalid input and therefore denies access.
// No groups.list permission or email/name-based correlation is used.
type googleSource struct {
	base   string
	groups []string
	oauth  *providerOAuth
}

var _ DirectorySource = (*googleSource)(nil)

func newGoogleSource(ctx context.Context, serviceAccountEmail, keyID string, privateKeyPEM []byte, delegatedSubject string, groupIDs []string, client *http.Client, now func() time.Time) (*googleSource, error) {
	return newGoogleSourceEndpoints(ctx, serviceAccountEmail, keyID, privateKeyPEM, delegatedSubject, groupIDs, client, now, "https://oauth2.googleapis.com/token", "https://admin.googleapis.com/admin/directory/v1")
}

// Endpoint injection is package-private for TLS fixtures, not deployment config.
func newGoogleSourceEndpoints(ctx context.Context, serviceAccountEmail, keyID string, privateKeyPEM []byte, delegatedSubject string, groupIDs []string, client *http.Client, now func() time.Time, tokenURL, base string) (*googleSource, error) {
	if serviceAccountEmail == "" || delegatedSubject == "" || len(groupIDs) > maxGroupPaths {
		return nil, errInvalidConfig
	}
	for _, id := range groupIDs {
		if !providerObjectID(id) {
			return nil, errInvalidConfig
		}
	}
	for _, endpoint := range []string{tokenURL, base} {
		u, err := url.Parse(endpoint)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return nil, errInvalidConfig
		}
	}
	p, err := newProviderOAuth(client, now)
	if err != nil {
		return nil, err
	}
	signer, err := providerSigner(privateKeyPEM, keyID)
	if err != nil {
		return nil, err
	}
	p.tokenURL = tokenURL
	p.retry = googleRetry
	p.form = func() (url.Values, error) {
		issued := now()
		assertion, err := jwt.Signed(signer).Claims(struct {
			jwt.Claims
			Scope string `json:"scope"`
		}{
			Claims: jwt.Claims{
				Issuer: serviceAccountEmail, Subject: delegatedSubject, Audience: jwt.Audience{tokenURL},
				IssuedAt: jwt.NewNumericDate(issued), Expiry: jwt.NewNumericDate(issued.Add(5 * time.Minute)),
			},
			Scope: "https://www.googleapis.com/auth/admin.directory.user.readonly https://www.googleapis.com/auth/admin.directory.group.member.readonly",
		}).Serialize()
		if err != nil {
			return nil, err
		}
		return url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {assertion}}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, directoryFetchTimeout)
	defer cancel()
	if _, err := p.token(ctx, ""); err != nil {
		return nil, err
	}
	return &googleSource{base: base, groups: dedupeGroups(groupIDs), oauth: p}, nil
}

func (s *googleSource) Observe(ctx context.Context, subject string) (directoryObservation, error) {
	if !providerObjectID(subject) {
		return directoryObservation{}, errDirectoryResponse
	}
	ctx, cancel := context.WithTimeout(ctx, directoryFetchTimeout)
	defer cancel()
	body, status, _, err := s.oauth.get(ctx, s.base+"/users/"+subject+"?projection=full&viewType=admin_view&fields=id,suspended,archived,deletionTime,name")
	if err != nil {
		return directoryObservation{}, err
	}
	if status == http.StatusNotFound || status == http.StatusGone {
		return directoryObservation{}, nil
	}
	if status != http.StatusOK {
		return directoryObservation{}, errDirectoryResponse
	}
	var user struct {
		ID           string `json:"id"`
		Suspended    *bool  `json:"suspended"`
		Archived     *bool  `json:"archived"`
		DeletionTime string `json:"deletionTime"`
		Name         struct {
			FullName string `json:"fullName"`
		} `json:"name"`
	}
	if json.Unmarshal(body, &user) != nil || user.ID != subject || user.Suspended == nil || user.Archived == nil {
		return directoryObservation{}, errDirectoryResponse
	}
	obs := directoryObservation{Found: true, UserID: subject, Direct: true, Enabled: !*user.Suspended && !*user.Archived && user.DeletionTime == "", DisplayName: sanitizeDisplay(user.Name.FullName)}
	if !obs.Enabled {
		return obs, nil
	}
	for _, group := range s.groups {
		body, status, _, err := s.oauth.get(ctx, s.base+"/groups/"+group+"/hasMember/"+subject)
		if err != nil {
			return directoryObservation{}, err
		}
		// A removed group cannot confer membership. Other errors, including
		// unsupported nested-domain checks, invalidate the entire observation.
		if status == http.StatusNotFound || status == http.StatusGone {
			continue
		}
		if status != http.StatusOK {
			return directoryObservation{}, errDirectoryResponse
		}
		var membership struct {
			IsMember *bool `json:"isMember"`
		}
		if json.Unmarshal(body, &membership) != nil || membership.IsMember == nil {
			return directoryObservation{}, errDirectoryResponse
		}
		if *membership.IsMember {
			obs.Groups = append(obs.Groups, group)
		}
	}
	return obs, nil
}

func googleRetry(status int, header http.Header, body []byte, attempt int, now time.Time) (time.Duration, bool, error) {
	retry := status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable
	if status == http.StatusForbidden {
		var response struct {
			Error struct {
				Errors []struct {
					Reason string `json:"reason"`
				} `json:"errors"`
			} `json:"error"`
		}
		if json.Unmarshal(body, &response) != nil {
			return 0, false, errDirectoryResponse
		}
		for _, detail := range response.Error.Errors {
			retry = retry || detail.Reason == "userRateLimitExceeded" || detail.Reason == "quotaExceeded" || detail.Reason == "rateLimitExceeded"
		}
	}
	if !retry {
		return 0, false, nil
	}
	// Follow Google's 2^n seconds + up to one second jitter, but never extend
	// the directory fetch deadline to complete the vendor's longer retry cycle.
	delay := time.Second*time.Duration(1<<attempt) + time.Duration(rand.IntN(1001))*time.Millisecond
	if value := header.Get("Retry-After"); value != "" {
		headerDelay, err := providerRetryAfter(value, now)
		if err != nil {
			return 0, false, err
		}
		delay = max(delay, headerDelay)
	}
	return delay, true, nil
}
