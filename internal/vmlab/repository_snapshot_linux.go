// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/vmlab/reposnapshot"
)

// tumbleweedInstallerLocale is the Tumbleweed AutoYaST profile's <language>;
// closure capture requests the same locale as the installer's solver.
const tumbleweedInstallerLocale = "en_US"

// RepositorySnapshotOptions runs inside the ordinary admitted disposable VM.
type RepositorySnapshotOptions struct {
	Capture                           reposnapshot.CaptureOptions
	CacheDir, WorkDir, DiagnosticsDir string
	Hardware                          *VMHardwareOptions
}

var snapshotPackageName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+_.:-]*$`)
var snapshotPackageVersion = regexp.MustCompile(`^([0-9]+:)?[A-Za-z0-9][A-Za-z0-9+_.~^-]*$`)

func validSnapshotSolverInput(input string) bool {
	name, version, pinned := strings.Cut(input, "=")
	return snapshotPackageName.MatchString(name) && (!pinned || snapshotPackageVersion.MatchString(version))
}

// CaptureRepositorySnapshot solves the clean target installation recipe and a
// distribution upgrade of the pinned base, then repeats both without origin
// access. No package is installed on the lab host.
func CaptureRepositorySnapshot(ctx context.Context, image *labv1.ImageManifest, o RepositorySnapshotOptions) (_ *labv1.RepositorySnapshotManifest, err error) {
	if o.CacheDir == "" {
		o.CacheDir = ".cache/lab/images"
	}
	o.CacheDir, err = filepath.Abs(o.CacheDir)
	if err != nil {
		return nil, err
	}
	if o.Capture.Cache == "" {
		o.Capture.Cache = o.CacheDir
	}
	o.Capture.Cache, err = filepath.Abs(o.Capture.Cache)
	if err != nil {
		return nil, err
	}
	if err := InitializeImageCache(ctx, o.CacheDir); err != nil {
		return nil, err
	}
	o.Capture.Distribution = image.Distribution
	o.Capture.Architecture = image.Architecture
	o.Capture.BaseImageSHA256 = image.Sha256
	if image.GetRepositorySnapshotManifestSha256() != "" {
		if image.GetRepositorySnapshotRepomdSha256() != o.Capture.RepomdSHA256 || image.GetRepositorySnapshotDate() != o.Capture.Date {
			return nil, errors.New("seed image snapshot pins differ from capture target")
		}
		o.Capture.SeedManifestSHA256 = image.GetRepositorySnapshotManifestSha256()
		o.Capture.SeedCache = o.CacheDir
	}
	capture, err := reposnapshot.NewCapture(ctx, o.Capture)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, capture.Close()) }()
	hardware, err := hardwareForManifest(image, o.Hardware, runtime.GOARCH)
	if err != nil {
		return nil, err
	}
	hardware.AllowNetwork = false
	vm, _, err := newRepositorySnapshotGuest(ctx, image, o.CacheDir, o.WorkDir, o.DiagnosticsDir, &hardware)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, vm.close()) }()
	inventory, err := vm.run(ctx, "rpm -qa --qf '%{NAME}\\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\n'", nil, 2<<20, time.Minute)
	if err != nil {
		return nil, err
	}
	var base []string
	for _, line := range strings.Split(strings.TrimSpace(string(inventory)), "\n") {
		name, _, ok := strings.Cut(line, "\t")
		if name == "gpg-pubkey" {
			continue
		}
		if !ok || !snapshotPackageName.MatchString(name) {
			return nil, errors.New("malformed pinned base package inventory")
		}
		base = append(base, line)
	}
	// The empty-root solve models the target golden recipe, not package names
	// from an older bootstrap. Native dist-upgrade on the copied base database
	// below handles package renames/obsoletes without ignoring missing inputs.
	inputs := capture.Manifest.RequestedPackages
	if len(base) > int(reposnapshot.HardMaxPackages) || len(inputs) > int(o.Capture.MaxPackages) {
		return nil, errors.New("base/requested input count exceeds package bound")
	}
	for _, input := range inputs {
		if !validSnapshotSolverInput(input) {
			return nil, errors.New("invalid solver package input")
		}
	}
	version, err := vm.run(ctx, "zypper --version", nil, 4096, time.Minute)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	server := &http.Server{Handler: capture, ReadHeaderTimeout: 15 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 16 << 10}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	defer func() {
		_ = server.Close()
		serveErr := <-serveDone
		if !errors.Is(serveErr, http.ErrServerClosed) {
			err = errors.Join(err, serveErr)
		}
	}()
	forward, err := newGuestForward(ctx, vm, "127.0.0.1:0", listener.Addr().String())
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, forward.Close()) }()
	repository, err := reposnapshot.RepositoryURL(forward.Addr())
	if err != nil {
		return nil, err
	}
	var transcript bytes.Buffer
	keys := capture.KeyPaths()
	slices.Sort(keys)
	if _, err := vm.run(ctx, "sudo -n install -d -m 0700 /var/tmp/lindm-repository-keys", nil, 1024, time.Minute); err != nil {
		return nil, err
	}
	for i, key := range keys {
		file, err := capture.OpenKey(key)
		if err != nil {
			return nil, err
		}
		destination := fmt.Sprintf("/var/tmp/lindm-repository-keys/key-%d", i)
		_, uploadErr := vm.run(ctx, "sudo -n sh -c "+nativeQuote("umask 077; cat > "+destination), io.LimitReader(file, (4<<20)+1), 1024, time.Minute)
		closeErr := file.Close()
		if uploadErr != nil || closeErr != nil {
			return nil, errors.Join(uploadErr, closeErr)
		}
	}
	for pass := range 2 {
		if pass == 1 {
			if err := capture.Offline(); err != nil {
				return nil, err
			}
		}
		for _, upgrade := range []bool{false, true} {
			root := fmt.Sprintf("/var/tmp/lindm-repository-closure-%d", pass)
			if upgrade {
				root += "-upgrade"
			}
			script := "set -eu\nexport LC_ALL=C\numask 077\nroot=" + nativeQuote(root) + "\nmkdir -m 700 \"$root\"\nmkdir -p \"$root/etc/zypp/repos.d\" \"$root/keys\" \"$root/usr/lib/sysimage/rpm\" \"$root/var/lib\" \"$root/var/cache/zypp\" \"$root/var/log/zypp\"\nif test -L /var/lib/rpm; then\ntest \"$(readlink -f /var/lib/rpm)\" = /usr/lib/sysimage/rpm\nln -s ../../usr/lib/sysimage/rpm \"$root/var/lib/rpm\"\nelse mkdir \"$root/var/lib/rpm\"; fi\n"
			// An alternate install root must carry the same native MAC file labels as
			// the real root; tmp_t is not a writable RPM database label. Enforcement is
			// never disabled, and no host policy or labels are changed.
			script += "if test -e /sys/fs/selinux/enforce; then\nchcon --reference=/ \"$root\"\nfor dir in /etc /etc/zypp /etc/zypp/repos.d /usr /usr/lib /usr/lib/sysimage /usr/lib/sysimage/rpm /var /var/lib /var/lib/rpm /var/cache /var/cache/zypp /var/log /var/log/zypp; do chcon --reference=\"$dir\" \"$root$dir\"; done\nchcon --reference=/etc \"$root/keys\"\nfi\n"
			if upgrade {
				script += "db=$(rpm --eval '%{_dbpath}')\ncase \"$db\" in /usr/lib/sysimage/rpm|/var/lib/rpm) ;; *) exit 1;; esac\ncp -a \"$db/.\" \"$root$db/\"\n"
			} else {
				script += "rpm --root \"$root\" --initdb\n"
			}
			for i := range keys {
				script += fmt.Sprintf("cp /var/tmp/lindm-repository-keys/key-%d \"$root/keys/key-%d\"\nrpm --root \"$root\" --import \"$root/keys/key-%d\"\n", i, i, i)
			}
			script += "printf '%s\\n' '[snapshot]' 'name=Authenticated bounded snapshot' 'enabled=1' 'autorefresh=0' 'gpgcheck=1' 'repo_gpgcheck=1' 'pkg_gpgcheck=1' " + nativeQuote("baseurl="+repository) + " > \"$root/etc/zypp/repos.d/snapshot.repo\"\n"
			// Request the installer's locale: libzypp selects "-lang" packages
			// supplementing requested locales, so a closure solved without one
			// lacked RPMs YaST then fetched (openconnect-lang on aarch64 GNOME).
			script += "mkdir -p \"$root/var/lib/zypp\"\nprintf '%s\\n' " + nativeQuote(tumbleweedInstallerLocale) + " > \"$root/var/lib/zypp/RequestedLocales\"\n"
			// Auto-import is confined to this authenticated proxy: it can expose only
			// the pinned key and keys delegated by the exact signed repomd, never a
			// mutable origin or an unverified guest repository.
			script += "zypper --root \"$root\" --non-interactive --gpg-auto-import-keys refresh\nzypper --root \"$root\" --non-interactive --gpg-auto-import-keys "
			if upgrade {
				script += "dist-upgrade --download-only --recommends\n"
			} else {
				script += "install --download-only --recommends"
				for _, name := range inputs {
					script += " " + nativeQuote(name)
				}
				script += "\n"
			}
			result, runErr := vm.runResult(ctx, "sudo -n sh -s", strings.NewReader(script), 8<<20, 90*time.Minute)
			if runErr != nil || result.ExitCode != 0 {
				cause := errors.Join(runErr, capture.Offline())
				if result.ExitCode != 0 {
					cause = errors.Join(cause, fmt.Errorf("native solver exited %d", result.ExitCode))
				}
				if o.DiagnosticsDir != "" {
					diagnostics, _ := vm.runResult(ctx, "sudo -n sh -c "+nativeQuote("id; ls -ldZ "+root+" "+root+"/usr/lib/sysimage/rpm; rpm --eval '%{_dbpath}'; journalctl --dmesg --since '-5 minutes' -n 100 --no-pager"), nil, 1<<20, time.Minute)
					data, marshalErr := json.Marshal(struct {
						Solver  guestCommandResult
						Native  guestCommandResult
						Failure string
					}{result, diagnostics, cause.Error()})
					if marshalErr != nil {
						return nil, errors.Join(cause, marshalErr)
					}
					saved, saveErr := saveGuestDiagnostics(o.DiagnosticsDir, data)
					return nil, errors.Join(fmt.Errorf("native zypper closure pass %d upgrade=%t: %w; private diagnostics %s", pass, upgrade, cause, saved), saveErr)
				}
				return nil, fmt.Errorf("native zypper closure pass %d upgrade=%t: %w; use -diagnostics DIR", pass, upgrade, cause)
			}
			fmt.Fprintf(&transcript, "PASS %d UPGRADE %t\n%s\n%s\n", pass, upgrade, result.Stdout, result.Stderr)
		}
		if pass == 0 {
			if _, err := vm.run(ctx, "sudo -n rm -rf -- /var/tmp/lindm-repository-closure-0 /var/tmp/lindm-repository-closure-0-upgrade", nil, 1024, time.Minute); err != nil {
				return nil, err
			}
		}
	}
	paths := capture.PackagePaths()
	if len(paths) == 0 {
		return nil, errors.New("native solver produced no RPM closure")
	}
	// rpmkeys runs natively with only authenticated repository keys in the replay
	// root. Verbose output must contain an actual successful signature, not merely
	// a successful unsigned digest check.
	script := "set -eu\nexport LC_ALL=C\nroot=/var/tmp/lindm-repository-closure-1\n"
	for _, p := range paths {
		_, name, _ := strings.Cut(p, "/")
		if strings.Contains(name, "/") {
			return nil, errors.New("unexpected nested RPM repository path")
		}
		script += "file=\"$root/var/cache/zypp/packages/snapshot/" + p + "\"\nif ! test -f \"$file\"; then file=\"$root-upgrade/var/cache/zypp/packages/snapshot/" + p + "\"; fi\ntest -f \"$file\"\noutput=$(rpmkeys --root \"$root\" --checksig --verbose \"$file\")\nprintf '%s\\n' \"$output\"\ncase \"$output\" in *'Signature'*': OK'*) ;; *) exit 1;; esac\ncase \"$output\" in *NOKEY*|*'NOT OK'*|*NOTTRUSTED*) exit 1;; esac\n"
		if strings.HasPrefix(name, "kernel-default-") {
			script += "printf '%s\\n' " + nativeQuote("SIGNED KERNEL HEADER "+p) + "\nrpm --query --package --queryformat '[%{FILENAMES}\\n]' \"$file\" > \"$root/kernel-header\"\nwhile IFS= read -r entry; do case \"$entry\" in /usr/lib/modules/*/config) printf '%s\\n' \"$entry\";; esac; done < \"$root/kernel-header\"\n"
		}
	}
	signatures, err := vm.run(ctx, "sudo -n sh -s", strings.NewReader(script), 8<<20, 20*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("native RPM signature validation: %w", err)
	}
	manifest, _, err := capture.Finish(base, strings.TrimSpace(string(version)), transcript.Bytes(), signatures)
	return manifest, err
}
