// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	sessionCookie       = "__Host-lindm_session"
	flowCookie          = "__Host-lindm_flow"
	csrfHeader          = "X-CSRF-Token"
	sessionDomain       = "lindm.session.v1"
	csrfDomain          = "lindm.csrf.v1"
	stateDomain         = "lindm.auth-state.v1"
	nonceDomain         = "lindm.auth-nonce.v1"
	bindingDomain       = "lindm.auth-binding.v1"
	flowCookieMaxAge    = 600
	sessionCookieMaxAge = 12 * 60 * 60
	opaqueTokenBytes    = 32
)

func randomToken() (string, error) {
	buf := make([]byte, opaqueTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func validOpaqueToken(v string) bool {
	if len(v) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(v)
	return err == nil && len(decoded) == opaqueTokenBytes
}

func domainHash(domain, value string) []byte {
	h := sha256.New()
	var n [2]byte
	binary.BigEndian.PutUint16(n[:], uint16(len(domain)))
	h.Write(n[:])
	h.Write([]byte(domain))
	h.Write([]byte{0})
	h.Write([]byte(value))
	return h.Sum(nil)
}

func sessionHash(cookie string) []byte { return domainHash(sessionDomain, cookie) }
func stateHash(state string) []byte    { return domainHash(stateDomain, state) }
func nonceHash(nonce string) []byte    { return domainHash(nonceDomain, nonce) }
func bindingHash(token string) []byte  { return domainHash(bindingDomain, token) }

func csrfToken(cookie string) string {
	return base64.RawURLEncoding.EncodeToString(domainHash(csrfDomain, cookie))
}

func csrfMatch(cookie, header string) bool {
	if cookie == "" || header == "" || len(header) > 128 {
		return false
	}
	want := csrfToken(cookie)
	if len(header) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(header), []byte(want)) == 1
}

func setHostCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearHostCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func readOpaqueCookie(r *http.Request, name string) (string, bool) {
	c, err := r.Cookie(name)
	if err != nil || c == nil || !validOpaqueToken(c.Value) {
		return "", false
	}
	return c.Value, true
}

func originMatches(configured, presented string) bool {
	if configured == "" || presented == "" || strings.ContainsAny(presented, " \t\r\n,") {
		return false
	}
	return presented == configured
}

func unsafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

func idTokenAccepted(clientID string, audience []string, azp, rawNonce string, wantNonce []byte, issuedAt, now time.Time) bool {
	if clientID == "" || rawNonce == "" || len(audience) == 0 || len(wantNonce) != sha256.Size {
		return false
	}
	for _, aud := range audience {
		if aud != clientID {
			return false
		}
	}
	if azp != "" && azp != clientID {
		return false
	}
	if subtle.ConstantTimeCompare(nonceHash(rawNonce), wantNonce) != 1 {
		return false
	}
	if issuedAt.IsZero() || issuedAt.After(now.Add(5*time.Minute)) {
		return false
	}
	return true
}

func parsePublicURL(raw string) (origin, redirect string, err error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", "", errInvalidConfig
	}
	if u.Path != "" && u.Path != "/" {
		return "", "", errInvalidConfig
	}
	origin = "https://" + canonicalHost(u)
	return origin, origin + "/auth/callback", nil
}

func canonicalHost(u *url.URL) string {
	host := u.Hostname()
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	port := u.Port()
	if port == "" || port == "443" {
		return host
	}
	return host + ":" + port
}
