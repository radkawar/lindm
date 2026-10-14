// SPDX-License-Identifier: Apache-2.0

package jobs

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestNewRejectsAmbiguousJobInventory(t *testing.T) {
	connection, err := pgx.ParseConfig("postgresql://runtime@localhost/lindm?application_name=operator")
	if err != nil {
		t.Fatal(err)
	}
	run := func(context.Context) error { return nil }
	for _, test := range []struct {
		name string
		jobs []Job
	}{
		{"empty", nil},
		{"unnamed", []Job{{Key: 1, Mode: Exclusive, Run: run}}},
		{"no run", []Job{{Name: "a", Key: 1, Mode: Exclusive}}},
		{"no mode", []Job{{Name: "a", Run: run}}},
		{"exclusive without key", []Job{{Name: "a", Mode: Exclusive, Run: run}}},
		{"replicated with key", []Job{{Name: "a", Key: 1, Mode: Replicated, Run: run}}},
		{"duplicate name", []Job{{Name: "a", Key: 1, Mode: Exclusive, Run: run}, {Name: "a", Key: 2, Mode: Exclusive, Run: run}}},
		{"duplicate key", []Job{{Name: "a", Key: 1, Mode: Exclusive, Run: run}, {Name: "b", Key: 1, Mode: Exclusive, Run: run}}},
	} {
		if _, err := New(Config{Connection: connection, Jobs: test.jobs}); err == nil {
			t.Errorf("%s: accepted", test.name)
		}
	}
	supervisor, err := New(Config{Connection: connection, Jobs: []Job{{Name: "a", Key: 1, Mode: Exclusive, Run: run}, {Name: "b", Mode: Replicated, Run: run}}})
	if err != nil {
		t.Fatal(err)
	}
	if name := supervisor.connection.RuntimeParams["application_name"]; !strings.HasPrefix(name, "lindmd jobs ") || len(name) > 63 {
		t.Fatalf("coordination session name %q", name)
	}
	if connection.RuntimeParams["application_name"] != "operator" {
		t.Fatal("supervisor mutated the caller's connection configuration")
	}
}

func TestBackoffIsBoundedAndJittered(t *testing.T) {
	for failures := 1; failures < 40; failures++ {
		ceiling := min(time.Second<<min(failures-1, 30), time.Minute)
		for range 20 {
			delay := backoff(time.Second, time.Minute, failures)
			if delay < ceiling/2 || delay > ceiling {
				t.Fatalf("failure %d delay %s outside [%s, %s]", failures, delay, ceiling/2, ceiling)
			}
		}
	}
	for range 100 {
		if delay := jitter(5 * time.Second); delay < 4*time.Second || delay > 6*time.Second {
			t.Fatalf("acquisition jitter %s", delay)
		}
	}
}
