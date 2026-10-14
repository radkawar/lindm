// SPDX-License-Identifier: Apache-2.0
//go:build linux

package vmlab

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestDeployDatabaseFailureClassificationNeverExportsDriverMessages(t *testing.T) {
	const canary = "private-password-and-connection-url"
	for _, test := range []struct {
		name           string
		err            error
		category, code string
	}{
		{"canceled", fmt.Errorf("%s: %w", canary, context.Canceled), "canceled", ""},
		{"deadline", fmt.Errorf("%s: %w", canary, context.DeadlineExceeded), "deadline", ""},
		{"authority", fmt.Errorf("%s: %w", canary, x509.UnknownAuthorityError{}), "tls_unknown_authority", ""},
		{"hostname", x509.HostnameError{Host: canary}, "tls_hostname", ""},
		{"certificate", x509.CertificateInvalidError{}, "tls_certificate", ""},
		{"sqlstate", &pgconn.PgError{Code: "28P01", Message: canary, Detail: canary}, "postgres", "28P01"},
		{"malformed_sqlstate", &pgconn.PgError{Code: canary, Message: canary}, "postgres", ""},
		{"malformed_short_sqlstate", &pgconn.PgError{Code: "a?cde", Message: canary}, "postgres", ""},
		{"unknown", errors.New(canary), "query", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			category, code := deployDatabaseErrorClassification(test.err)
			if category != test.category || code != test.code || strings.Contains(category+code, canary) {
				t.Fatalf("unsafe or incorrect fixed diagnostic: category=%q code=%q", category, code)
			}
		})
	}
}
