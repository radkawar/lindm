package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConsoleBrowserConfigCustody(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "capture.json")
	data := []byte(`{"password":"private-owner-secret","origin":"https://localhost:18444"}`)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	var cfg acceptanceBrowserConfig
	if err := readConsoleBrowserJSON(path, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Password != "private-owner-secret" || cfg.Origin != "https://localhost:18444" {
		t.Fatal("browser config changed")
	}
	link := filepath.Join(root, "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := readConsoleBrowserJSON(link, &cfg); err == nil {
		t.Fatal("symlink browser credentials accepted")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if err := readConsoleBrowserJSON(path, &cfg); err == nil {
		t.Fatal("public browser credentials accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"password":"private-owner-secret"`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := readConsoleBrowserJSON(path, &cfg); err == nil || strings.Contains(err.Error(), "private-owner-secret") {
		t.Fatal("malformed config accepted or credential disclosed")
	}
}
