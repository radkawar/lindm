//go:build linux && integration && dnfcapture

package vmlab_test

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"lindm/internal/labhost"
	"lindm/internal/vmlab"
)

var dnfCaptureHost = flag.String("host", "", "explicit executing lab host for the opt-in DNF native capture")

// TestDNFNativeCapture records real native interfaces, including unsupported
// operations, from an unmodified pinned image. It neither installs packages nor
// treats a failed query as successful empty inventory. Output is private because
// native repository configuration can contain sensitive URLs.
func TestDNFNativeCapture(t *testing.T) {
	manifestPath := os.Getenv("LINDM_DNF_CAPTURE_MANIFEST")
	output := os.Getenv("LINDM_DNF_CAPTURE_OUTPUT")
	if manifestPath == "" || output == "" || *dnfCaptureHost == "" {
		t.Fatal("requires LINDM_DNF_CAPTURE_MANIFEST, a new LINDM_DNF_CAPTURE_OUTPUT directory, and an explicit -host")
	}
	manifest, err := vmlab.LoadManifest(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.GetDistribution() != "fedora" {
		t.Fatal("DNF capture requires a pinned Fedora image without enrollment credentials")
	}
	architecture, err := labhost.NormalizeArchitecture(manifest.GetArchitecture())
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := labhost.Load()
	if err != nil {
		t.Fatal(err)
	}
	hosts, err := labhost.Select(cfg, &labhost.Requirements{Host: *dnfCaptureHost, Architecture: architecture, Vcpus: 2, MemoryMib: 2048, RequireKVM: true})
	if err != nil {
		t.Fatal(err)
	}
	host := hosts[0]
	if host.GetTransport() != "local" || host.GetRuntime() != "native" {
		t.Fatal("capture requires native local transport")
	}
	work, err := labhost.ResolveWorkDirectory(host)
	if err != nil {
		t.Fatal(err)
	}
	slots, err := labhost.OpenSlots(host)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Minute)
	defer cancel()
	lease, err := slots.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := lease.Close(); err != nil {
			t.Error(err)
		}
	}()
	cache := os.Getenv("LINDM_DNF_CAPTURE_CACHE")
	if cache == "" {
		cache = filepath.Join("..", "..", ".cache", "lab", "images")
	}
	vmlab.CaptureDNFNativeForTest(t, ctx, manifest, manifestPath, cache, work, output, host)
}
