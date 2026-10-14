// SPDX-License-Identifier: Apache-2.0

//go:build integration

package testdb

import (
	"os"
	"strings"
	"testing"

	"lindm/internal/custody"
)

// BenchmarkMigrationFixtures compares the original migration-per-case path with
// a logical template restore, including independent connections and cleanup.
func BenchmarkMigrationFixtures(b *testing.B) {
	path := os.Getenv("LINDM_TEST_DATABASE_URL_FILE")
	if _, err := custody.Owned(path, false); err != nil {
		b.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		b.Fatal(err)
	}
	defer clear(data)
	dsn := strings.TrimSpace(string(data))
	template, err := migratedTemplate(b.Context())
	if err != nil {
		b.Fatal(err)
	}
	for _, name := range []string{"migrate", "template"} {
		b.Run(name, func(b *testing.B) {
			var timings fixtureTimings
			for range b.N {
				var database *Database
				var err error
				if name == "migrate" {
					database, err = New(b.Context(), dsn)
				} else {
					database, err = NewFromTemplate(b.Context(), dsn, template)
				}
				if err != nil {
					b.Fatal(err)
				}
				timings.create += database.timings.create
				timings.initialize += database.timings.initialize
				timings.check += database.timings.check
				timings.connect += database.timings.connect
				if err := database.Close(); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(timings.create.Seconds()/float64(b.N), "create_s/op")
			b.ReportMetric(timings.initialize.Seconds()/float64(b.N), "initialize_s/op")
			b.ReportMetric(timings.check.Seconds()/float64(b.N), "check_s/op")
			b.ReportMetric(timings.connect.Seconds()/float64(b.N), "connect_s/op")
		})
	}
}
