package main

import (
	"errors"
	"os"
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
