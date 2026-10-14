// SPDX-License-Identifier: Apache-2.0

package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	updatev1 "lindm/gen/lindm/update/v1"
	"lindm/internal/config"
	"lindm/internal/releaseupdate"
)

func TestReleaseRepositoryReadOnlyWithoutSession(t *testing.T) {
	directory, custody := t.TempDir(), t.TempDir()
	for _, path := range []string{directory, custody} {
		if err := os.Chmod(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := releaseupdate.GenerateDevelopmentKeys(custody); err != nil {
		t.Fatal(err)
	}
	signers, err := releaseupdate.LoadRoleSigners(custody, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := releaseupdate.CreateRepository(t.Context(), releaseupdate.PublisherConfig{Directory: directory, Signers: signers, Now: time.Now}); err != nil {
		t.Fatal(err)
	}
	handler, publisher, err := newReleaseRepository(&config.Resources{ReleaseRepositoryDirectory: directory})
	if err != nil || publisher != nil {
		t.Fatalf("read-only hosting requires signer: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/updates/", http.StripPrefix("/updates/", handler))
	for _, test := range []struct {
		method, path string
		status       int
	}{{"GET", "/updates/metadata/1.root.json", 200}, {"HEAD", "/updates/metadata/timestamp.json", 200}, {"POST", "/updates/metadata/timestamp.json", 405}, {"GET", "/updates/metadata/", 404}, {"GET", "/updates/targets/", 404}, {"GET", "/updates/root.pem", 404}, {"GET", "/updates/metadata/private.pem", 404}} {
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, httptest.NewRequest(test.method, test.path, nil))
		if response.Code != test.status {
			t.Fatalf("%s %s: %d", test.method, test.path, response.Code)
		}
	}
	// A served metadata-looking symlink must not escape to an arbitrary secret.
	if err := os.Symlink(filepath.Join(custody, "root.pem"), filepath.Join(directory, "metadata", "9.root.json")); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest("GET", "/updates/metadata/9.root.json", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("private symlink served: %d", response.Code)
	}
	result := response.Result()
	if _, err := io.Copy(io.Discard, result.Body); err != nil {
		t.Fatal(err)
	}
	if err := result.Body.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestReleaseRepositoryRejectsPublishedCustody(t *testing.T) {
	directory := t.TempDir()
	custody := filepath.Join(directory, "private")
	if err := os.Mkdir(custody, 0700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := newReleaseRepository(&config.Resources{ReleaseRepositoryDirectory: directory, ReleaseSigningDirectory: custody}); err == nil {
		t.Fatal("private signing directory admitted inside repository")
	}
}

func TestReleaseServerHasOnlyDelegatedRolloutCustody(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "repository")
	offline := filepath.Join(root, "offline")
	online := filepath.Join(root, "online")
	if err := releaseupdate.GenerateDevelopmentKeys(offline); err != nil {
		t.Fatal(err)
	}
	signers, err := releaseupdate.LoadRoleSigners(offline, true)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := releaseupdate.CreateRepository(t.Context(), releaseupdate.PublisherConfig{Directory: directory, Signers: signers, Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(online, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"rollout.pem", "snapshot.pem", "timestamp.pem"} {
		key, err := os.ReadFile(filepath.Join(offline, name))
		if err != nil {
			t.Fatal(err)
		}
		err = os.WriteFile(filepath.Join(online, name), key, 0600)
		clear(key)
		if err != nil {
			t.Fatal(err)
		}
	}
	artifact := filepath.Join(root, "agent.deb")
	if err := os.WriteFile(artifact, []byte("opaque release target, not native package evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	target := "packages/lindm-agent/1.3.0/amd64.deb"
	now := time.Now().UTC()
	channel := &updatev1.AgentUpdateChannel{
		Ring: "canary", Generation: 1, EligiblePercentage: 100,
		IssuedAt: timestamppb.New(now.Add(-time.Minute)), ExpiresAt: timestamppb.New(now.Add(time.Hour)),
		Artifacts: []*updatev1.AgentUpdateArtifact{{
			Version: "1.3.0", NativeVersion: "1.3.0-1", Architecture: "amd64", PackageFormat: "deb",
			TargetPath: target, MinimumAgentVersion: "1.0.0", MaximumAgentVersion: "1.3.0",
			MinimumProtocolVersion: 1, MaximumProtocolVersion: 1,
		}},
	}
	if err := publisher.Publish(t.Context(), channel, map[string]string{target: artifact}); err != nil {
		t.Fatal(err)
	}
	resources := &config.Resources{ReleaseRepositoryDirectory: directory, ReleaseSigningDirectory: online}
	handler, serverPublisher, err := newReleaseRepository(resources)
	if err != nil || handler == nil || serverPublisher == nil {
		t.Fatalf("online-only server initialization: %v", err)
	}
	paused, err := serverPublisher.SetRollout(t.Context(), "canary", true, 25)
	if err != nil || !paused.GetPaused() || paused.GetGeneration() != 2 || paused.GetEligiblePercentage() != 25 {
		t.Fatalf("delegated rollout mutation failed: %v", err)
	}
	if !proto.Equal(paused.GetArtifacts()[0], channel.GetArtifacts()[0]) {
		t.Fatal("online rollout changed the offline artifact contract")
	}
	unauthorized := proto.CloneOf(paused)
	unauthorized.Generation++
	unauthorized.Artifacts[0].MaximumProtocolVersion = 2
	if err := serverPublisher.Publish(t.Context(), unauthorized, map[string]string{target: artifact}); err == nil {
		t.Fatal("server publisher acquired offline targets authority")
	}
	current, err := serverPublisher.Channel(t.Context(), "canary")
	if err != nil || !proto.Equal(current, paused) {
		t.Fatalf("denied package publication changed signed channel: %v", err)
	}
	for _, name := range []string{"root.pem", "targets.pem"} {
		t.Run(name, func(t *testing.T) {
			// Presence is forbidden even if the online loader could otherwise
			// ignore this valid private key and complete startup.
			key, err := os.ReadFile(filepath.Join(offline, name))
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(online, name)
			err = os.WriteFile(path, key, 0600)
			clear(key)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := newReleaseRepository(resources); err == nil {
				t.Fatal("server admitted offline private custody")
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(offline, name), path); err != nil {
				t.Fatal(err)
			}
			if _, _, err := newReleaseRepository(resources); err == nil {
				t.Fatal("server admitted symlink to offline custody")
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		})
	}
}
