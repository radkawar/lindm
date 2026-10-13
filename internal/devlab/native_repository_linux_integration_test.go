//go:build integration && linux

package devlab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"connectrpc.com/connect"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/config"
	"lindm/internal/packaging"
)

// This regression starts real lindmd with its signed source-built artifact and
// no release repository configuration. It does not claim native installation;
// the separate enroll-from-console VM lane must execute the browser clipboard.
func TestStockConsoleAgentRepositoryWithoutConfiguration(t *testing.T) {
	binary, repository := nativeServer(t)
	source, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Minute)
	defer cancel()
	fixture, err := OpenStockConsoleAuthorityFixture(ctx, repository, source, binary)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := fixture.Close(); err != nil {
			t.Error(err)
		}
	}()
	document, err := config.Load(fixture.configPath())
	if err != nil {
		t.Fatal(err)
	}
	if document.Proto.GetReleaseRepository() != nil {
		t.Fatal("fresh stock console configured a release repository")
	}
	publication := fixture.NativeRepository
	if publication == nil || !publication.Ready || publication.NativeRepositoriesConfigured || publication.ReleaseRepositoryConfigured {
		t.Fatalf("fresh stock console lacks observed no-config readiness: %+v", publication)
	}
	if fixture.binary == binary || filepath.Dir(fixture.binary) != filepath.Dir(publication.BundleDirectory) {
		t.Fatal("fixture did not isolate the server beside its signed agent bundle")
	}
	if _, err := os.Lstat(filepath.Join(fixture.directory, "native-package-custody")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("development native signing custody remained after server startup")
	}
	owner, err := fixture.OpenOwnerSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := closeReleaseSession(owner); err != nil {
			t.Error(err)
		}
	}()
	instructions, err := owner.Admin.GetEnrollmentInstructions(ctx, connect.NewRequest(&adminv1.GetEnrollmentInstructionsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if !instructions.Msg.GetReadiness().GetReady() || instructions.Msg.GetAptRepository().GetBaseUrl() != publication.APTURL {
		t.Fatal("authenticated enrollment instructions did not publish the stock APT repository")
	}
	// Give the negative fixture the stock executable, which has a valid adjacent
	// bundle. It must isolate that binary rather than inherit another lab's Ready.
	missing, err := OpenMissingArtifactConsoleAuthorityFixture(ctx, repository, fixture.binary)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := missing.Close(); err != nil {
			t.Error(err)
		}
	}()
	if missing.binary == fixture.binary || filepath.Dir(missing.binary) != missing.directory {
		t.Fatal("missing artifact console borrowed the stock executable or bundle")
	}
	missingDocument, err := config.Load(missing.configPath())
	if err != nil {
		t.Fatal(err)
	}
	if missingDocument.Proto.GetReleaseRepository() != nil {
		t.Fatal("missing artifact console added repository configuration")
	}
	missingOwner, err := missing.OpenOwnerSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := closeReleaseSession(missingOwner); err != nil {
			t.Error(err)
		}
	}()
	unavailable, err := missingOwner.Admin.GetEnrollmentInstructions(ctx, connect.NewRequest(&adminv1.GetEnrollmentInstructionsRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	if unavailable.Msg.GetReadiness().GetReady() || unavailable.Msg.GetReadiness().GetReason() != "native_repository_unavailable" {
		t.Fatal("console without an artifact offered installation readiness")
	}
	if unavailable.Msg.GetAptRepository() != nil || unavailable.Msg.GetDnfRepository() != nil || unavailable.Msg.GetArchRepository() != nil {
		t.Fatal("console without an artifact offered native repository instructions")
	}
	for _, target := range unavailable.Msg.GetPlatforms() {
		if target.GetId() == "ubuntu-24.04" || target.GetId() == "fedora-44" {
			if target.GetReadiness().GetReady() || target.GetReadiness().GetReason() != "native_repository_unavailable" {
				t.Fatalf("missing artifact target %s offered an install command", target.GetId())
			}
		}
	}
	var path, digest string
	var size int64
	for _, artifact := range publication.Manifest.GetArtifacts() {
		if artifact.GetProduct() != packaging.PackageName {
			t.Fatal("stock fixture agent bundle includes another product")
		}
		if artifact.GetFormat() == string(packaging.FormatDEB) && artifact.GetArchitecture() == runtime.GOARCH {
			path, digest, size = artifact.GetPath(), artifact.GetSha256(), artifact.GetSize()
		}
	}
	if path == "" {
		t.Fatal("signed stock manifest lacks the native agent package")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, publication.APTURL+"/pool/main/l/lindm-agent/"+filepath.Base(path), nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := owner.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("stock agent package returned HTTP %d", response.StatusCode)
	}
	hash := sha256.New()
	count, err := io.Copy(hash, io.LimitReader(response.Body, size+1))
	if err != nil {
		t.Fatal(err)
	}
	if count != size || hex.EncodeToString(hash.Sum(nil)) != digest {
		t.Fatal("served native agent package differs from its verified release manifest")
	}
	t.Logf("stock console Ready without releaseRepository; native %s DEB digest=%s", runtime.GOARCH, digest)
}
