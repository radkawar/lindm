package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"lindm/internal/vmlab"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "lab:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) >= 2 && args[0] == "vm" && args[1] == "inspect" {
		return runVMInspect(ctx, args[2:], stdout, stderr)
	}
	if len(args) < 2 || args[0] != "images" || (args[1] != "fetch" && args[1] != "verify") {
		return errors.New("usage: lab vm inspect -manifest FILE -agent FILE [-cache DIR] [-work-dir DIR]; lab images {fetch|verify} -manifest FILE [-cache DIR]; verify also accepts -image FILE -checksum FILE -key FILE [-signature FILE]")
	}
	flags := flag.NewFlagSet("images "+args[1], flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifestPath := flags.String("manifest", "", "strict protobuf JSON image manifest")
	cache := flags.String("cache", ".cache/lab/images", "dedicated digest-addressed image cache")
	var files vmlab.Artifacts
	if args[1] == "verify" {
		flags.StringVar(&files.Image, "image", "", "existing image to verify offline instead of the cache")
		flags.StringVar(&files.Checksum, "checksum", "", "existing vendor checksum file")
		flags.StringVar(&files.Signature, "signature", "", "existing detached checksum signature (Ubuntu only)")
		flags.StringVar(&files.Key, "key", "", "existing vendor public key or keyring")
	}
	if err := flags.Parse(args[2:]); err != nil {
		return err
	}
	if *manifestPath == "" || flags.NArg() != 0 {
		return errors.New("-manifest FILE is required; positional arguments are not accepted")
	}
	direct := files.Image != "" || files.Checksum != "" || files.Key != "" || files.Signature != ""
	if direct {
		if files.Image == "" || files.Checksum == "" || files.Key == "" {
			return errors.New("offline artifact verification requires -image, -checksum and -key")
		}
		cacheSet := false
		flags.Visit(func(f *flag.Flag) {
			if f.Name == "cache" {
				cacheSet = true
			}
		})
		if cacheSet {
			return errors.New("choose either -cache or explicit artifact files, not both")
		}
	}
	manifest, err := vmlab.LoadManifest(*manifestPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 40*time.Minute)
	defer cancel()
	var verified *vmlab.VerifiedImage
	if args[1] == "fetch" {
		verified, err = (vmlab.Fetcher{}).Fetch(ctx, manifest, *cache)
	} else if direct {
		if (manifest.SignatureUrl != nil) != (files.Signature != "") {
			return errors.New("-signature is required exactly when the manifest uses detached checksums")
		}
		verified, err = vmlab.VerifyArtifacts(ctx, manifest, files)
	} else {
		verified, err = vmlab.VerifyCache(ctx, manifest, *cache)
	}
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "verified %s\nsha256 %s\nbytes %d\nsigner %s\nprimary %s\nimage %q\n", manifest.Id, verified.SHA256, verified.Size, verified.SigningFingerprint, verified.PrimaryFingerprint, verified.Path)
	return err
}

func runVMInspect(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("vm inspect", flag.ContinueOnError)
	flags.SetOutput(stderr)
	manifestPath := flags.String("manifest", "", "strict protobuf JSON image manifest")
	agent := flags.String("agent", "", "built Linux amd64 lindm-agent executable")
	cache := flags.String("cache", ".cache/lab/images", "dedicated verified image cache")
	workDir := flags.String("work-dir", "", "existing parent for a disposable private run directory (default: OS temporary directory)")
	diagnosticsDir := flags.String("diagnostics", "", "existing directory for opt-in private cloud-init failure JSON; may contain sensitive guest data")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *manifestPath == "" || *agent == "" || flags.NArg() != 0 {
		return errors.New("-manifest FILE and -agent FILE are required; positional arguments are not accepted")
	}
	manifest, err := vmlab.LoadManifest(*manifestPath)
	if err != nil {
		return err
	}
	result, err := vmlab.InspectVM(ctx, manifest, vmlab.VMInspectOptions{Agent: *agent, CacheDir: *cache, WorkDir: *workDir, DiagnosticsDir: *diagnosticsDir})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "native inspection matched: %s %s; %d complete package records; OS/kernel/boot/hostname matched\nimage %s\nimage_sha256 %s\nagent_sha256 %s\ncleanup complete; inspection only, not installation/enrollment or OS support certification\n", result.Distribution, result.Version, result.MatchedPackages, result.ImageID, result.ImageSHA256, result.AgentSHA256)
	return err
}
