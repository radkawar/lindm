// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"errors"
	"io"
	"mime"
	"net/http"

	"google.golang.org/protobuf/encoding/protojson"

	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/rpcreason"
)

func (s *Service) handleSetupBegin(w http.ResponseWriter, r *http.Request) {
	prepare(w)
	// Explicit origin plus a non-simple header excludes browser form and CSRF
	// requests. Fetch metadata is an additional check, never an identity source.
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if !s.localPrimary || !originMatches(s.publicOrigin, r.Header.Get("Origin")) ||
		r.Header.Get("X-Lindm-Setup") != "1" || media != "application/json" || err != nil ||
		(r.Header.Get("Sec-Fetch-Site") != "" && r.Header.Get("Sec-Fetch-Site") != "same-origin") {
		writeStatus(w, http.StatusForbidden)
		return
	}
	if err = s.admitSetup(r.Context(), r.RemoteAddr); err != nil {
		if errors.Is(err, errSetupRateLimited) {
			w.Header().Set("Retry-After", "60")
			w.Header().Set(rpcreason.Header, "setup_rate_limited")
			writeStatus(w, http.StatusTooManyRequests)
			return
		}
		writeStatus(w, statusFor(err))
		return
	}
	request := &authv1.FirstRunSetupRequest{}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8*1024))
	if err != nil || protojson.Unmarshal(body, request) != nil || s.rules.Validate(request) != nil {
		writeStatus(w, http.StatusBadRequest)
		return
	}
	challenge, err := s.beginSetup(r.Context(), request)
	if err != nil {
		if errors.Is(err, errUnauthenticated) {
			w.Header().Set(rpcreason.Header, "setup_not_authorized")
		}
		writeStatus(w, statusFor(err))
		return
	}
	writeProto(w, challenge)
}
