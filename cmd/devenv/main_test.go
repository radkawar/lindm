package main

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestRecreateDatabaseArguments(t *testing.T) {
	original := os.Args
	t.Cleanup(func() { os.Args = original })
	for _, args := range [][]string{
		{"recreate-database"},
		{"recreate-database", "-confirm-delete=false"},
		{"recreate-database", "-confirm-delete", "lindm_authority_other"},
		{"recreate-database", "-confirm-delete", "-database", "postgres"},
	} {
		os.Args = append([]string{"dev"}, args...)
		if err := run(); err == nil {
			t.Fatalf("accepted unsafe arguments %v", args)
		}
	}
	// With consent, parsing reaches fixture lookup, without contacting Docker.
	os.Args = []string{"dev", "recreate-database", "-confirm-delete", "-root", t.TempDir()}
	if err := run(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("confirmed command did not reach fixture validation: %v", err)
	}
}

func TestIntegrationTimeoutIsCapped(t *testing.T) {
	original := os.Args
	t.Cleanup(func() { os.Args = original })
	os.Args = []string{"dev", "test-integration", "-timeout", "46m", "-root", t.TempDir()}
	if err := run(); err == nil || !strings.Contains(err.Error(), "cap") {
		t.Fatalf("a 46m integration lock hold was accepted: %v", err)
	}
}
