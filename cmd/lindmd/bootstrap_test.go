// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"lindm/internal/identity"
)

func TestPrintEnrollmentKeepsSecretOutOfURL(t *testing.T) {
	enrollment := identity.Enrollment{Secret: "one-use-enrollment-secret", ExpiresAt: time.Date(2026, 10, 9, 12, 30, 0, 0, time.UTC), AccountID: uuid.New()}
	for _, origin := range []string{"https://console.example", "https://console.example/"} {
		var output bytes.Buffer
		if err := printEnrollment(&output, origin, enrollment); err != nil {
			t.Fatal(err)
		}
		text := output.String()
		urlLine, _, _ := strings.Cut(text, "\n")
		if urlLine != "Enrollment URL: https://console.example/enroll" {
			t.Fatalf("unexpected enrollment URL: %s", urlLine)
		}
		if strings.Count(text, enrollment.Secret) != 1 {
			t.Fatal("enrollment secret was not printed exactly once")
		}
		if !strings.Contains(text, enrollment.ExpiresAt.Format(time.RFC3339)) || !strings.Contains(text, enrollment.AccountID.String()) {
			t.Fatal("enrollment expiry or account identity missing")
		}
	}
}

func TestPrintEnrollmentReportsOutputFailure(t *testing.T) {
	if err := printEnrollment(failingEnrollmentWriter{}, "https://console.example", identity.Enrollment{}); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("output failure = %v", err)
	}
}

type failingEnrollmentWriter struct{}

func (failingEnrollmentWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
