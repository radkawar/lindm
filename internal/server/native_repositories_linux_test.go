// SPDX-License-Identifier: Apache-2.0

//go:build linux

package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/config"
)

// These fixtures exercise native metadata authentication and HTTP delivery, not
// package installation. Native DEB/RPM/pacman transactions belong to the VM lab.
type nativeFixture struct {
	directory   string
	key         *openpgp.Entity
	fingerprint string
}

func newNativeFixture(t *testing.T) *nativeFixture {
	t.Helper()
	key, err := openpgp.NewEntity("Native repository regression", "", "native@example.test", &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
	if err != nil {
		t.Fatal(err)
	}
	return &nativeFixture{directory: t.TempDir(), key: key, fingerprint: strings.ToUpper(hex.EncodeToString(key.PrimaryKey.Fingerprint))}
}

func (f *nativeFixture) write(t *testing.T, family, name string, data []byte) {
	t.Helper()
	filename := filepath.Join(f.directory, "repo", family, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func (f *nativeFixture) public(t *testing.T, family string) {
	t.Helper()
	var public bytes.Buffer
	writer, err := armor.Encode(&public, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.key.Serialize(writer); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	f.write(t, family, nativePublicKey, public.Bytes())
}

func (f *nativeFixture) sign(t *testing.T, data []byte, armored bool) []byte {
	t.Helper()
	var signature bytes.Buffer
	if armored {
		if err := openpgp.ArmoredDetachSign(&signature, []*openpgp.Entity{f.key}, bytes.NewReader(data), nil); err != nil {
			t.Fatal(err)
		}
	} else if err := openpgp.DetachSign(&signature, []*openpgp.Entity{f.key}, bytes.NewReader(data), nil); err != nil {
		t.Fatal(err)
	}
	return signature.Bytes()
}

func nativeTestDigest(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func nativeTestGzip(t *testing.T, data []byte) []byte {
	t.Helper()
	var result bytes.Buffer
	gz := gzip.NewWriter(&result)
	if _, err := gz.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return result.Bytes()
}

func (f *nativeFixture) apt(t *testing.T, arch string) string {
	t.Helper()
	f.public(t, "apt")
	name := "pool/main/l/lindm-agent/lindm-agent_1.0.0_" + arch + ".deb"
	payload := []byte("native delivery fixture for " + arch)
	f.write(t, "apt", name, payload)
	packages := []byte(fmt.Sprintf("Package: lindm-agent\nVersion: 1.0.0\nArchitecture: %s\nFilename: %s\nSize: %d\nSHA256: %s\n\n", arch, name, len(payload), nativeTestDigest(payload)))
	index := "main/binary-" + arch + "/Packages"
	f.write(t, "apt", "dists/stable/"+index, packages)
	compressed := nativeTestGzip(t, packages)
	f.write(t, "apt", "dists/stable/"+index+".gz", compressed)
	release := []byte(fmt.Sprintf("Suite: stable\nArchitectures: %s\nComponents: main\nSHA256:\n %s %d %s\n %s %d %s.gz\n", arch, nativeTestDigest(packages), len(packages), index, nativeTestDigest(compressed), len(compressed), index))
	f.write(t, "apt", "dists/stable/Release", release)
	f.write(t, "apt", "dists/stable/Release.gpg", f.sign(t, release, true))
	var signed bytes.Buffer
	writer, err := clearsign.Encode(&signed, f.key.PrivateKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(release); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	f.write(t, "apt", "dists/stable/InRelease", signed.Bytes())
	return name
}

func (f *nativeFixture) rpm(t *testing.T, arch string) string {
	t.Helper()
	f.public(t, "rpm")
	name := "lindm-agent-1.0.0-1." + arch + ".rpm"
	payload := []byte("native RPM delivery fixture for " + arch)
	f.write(t, "rpm", name, payload)
	primary := []byte(fmt.Sprintf(`<metadata xmlns="http://linux.duke.edu/metadata/common"><package type="rpm"><name>lindm-agent</name><arch>%s</arch><version epoch="0" ver="1.0.0" rel="1"/><checksum type="sha256">%s</checksum><size package="%d"/><location href="%s"/></package></metadata>`, arch, nativeTestDigest(payload), len(payload), name))
	compressed := nativeTestGzip(t, primary)
	index := "repodata/" + nativeTestDigest(compressed) + "-primary.xml.gz"
	f.write(t, "rpm", index, compressed)
	repomd := []byte(fmt.Sprintf(`<repomd xmlns="http://linux.duke.edu/metadata/repo"><data type="primary"><checksum type="sha256">%s</checksum><location href="%s"/></data></repomd>`, nativeTestDigest(compressed), index))
	f.write(t, "rpm", "repodata/repomd.xml", repomd)
	f.write(t, "rpm", "repodata/repomd.xml.asc", f.sign(t, repomd, true))
	return name
}

func (f *nativeFixture) arch(t *testing.T) string {
	t.Helper()
	f.public(t, "arch")
	name := "lindm-agent-1.0.0-1-x86_64.pkg.tar.zst"
	payload := []byte("native Arch delivery fixture")
	signature := f.sign(t, payload, false)
	f.write(t, "arch", name, payload)
	f.write(t, "arch", name+".sig", signature)
	desc := []byte(fmt.Sprintf("%%FILENAME%%\n%s\n\n%%NAME%%\nlindm-agent\n\n%%VERSION%%\n1.0.0-1\n\n%%ARCH%%\nx86_64\n\n%%CSIZE%%\n%d\n\n%%SHA256SUM%%\n%s\n\n%%PGPSIG%%\n%s\n\n", name, len(payload), nativeTestDigest(payload), base64.StdEncoding.EncodeToString(signature)))
	var tarball bytes.Buffer
	tw := tar.NewWriter(&tarball)
	if err := tw.WriteHeader(&tar.Header{Name: "lindm-agent-1.0.0-1/desc", Mode: 0644, Size: int64(len(desc)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(desc); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	database := nativeTestGzip(t, tarball.Bytes())
	f.write(t, "arch", "lindm.db", database)
	f.write(t, "arch", "lindm.db.sig", f.sign(t, database, false))
	return name
}

func (f *nativeFixture) resources() *config.Resources {
	return &config.Resources{ReleaseRepositoryDirectory: f.directory, Proto: &configv1.ServerConfig{
		PublicUrl: "https://console.example/", DevicePublicUrl: proto.String("https://devices.example:9443"),
		ReleaseRepository: &configv1.ReleaseRepositoryConfig{Directory: f.directory, NativeRepositories: &configv1.NativeRepositoriesConfig{
			AptSigningKeyFingerprint: proto.String(f.fingerprint), RpmSigningKeyFingerprint: proto.String(f.fingerprint), ArchSigningKeyFingerprint: proto.String(f.fingerprint),
		}},
	}, ExecutionBootstrap: &config.ExecutionBootstrap{RootJSON: []byte("authenticated root"), Envelope: []byte("signed bundle")}}
}

func TestNativeRepositoryAuthenticatedReadOnlyDelivery(t *testing.T) {
	f := newNativeFixture(t)
	for family, name := range map[string]string{"apt": f.apt(t, "arm64"), "rpm": f.rpm(t, "aarch64"), "arch": f.arch(t)} {
		t.Run(family, func(t *testing.T) {
			repo := loadNativeRepository(t.Context(), f.directory, family, f.fingerprint)
			if repo.err != nil {
				t.Fatal(repo.err)
			}
			arch := "arm64"
			if family == "arch" {
				arch = "amd64"
			}
			if !slices.Equal(repo.architectures, []string{arch}) {
				t.Fatalf("architectures = %v", repo.architectures)
			}
			version := "1.0.0-1"
			if family == "apt" {
				version = "1.0.0"
			}
			if !slices.Equal(repo.versions[arch], []string{version}) {
				t.Fatalf("versions = %v", repo.versions)
			}
			handler := http.StripPrefix("/repo/"+family+"/", repo)
			url := "https://untrusted-host.example/repo/" + family + "/" + name
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, url, nil))
			if response.Code != http.StatusOK || response.Body.Len() == 0 || response.Header().Get("ETag") == "" || !strings.Contains(response.Header().Get("Cache-Control"), "public") {
				t.Fatalf("public GET: %d %v", response.Code, response.Header())
			}
			etag := response.Header().Get("ETag")
			response = httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodHead, url, nil))
			if response.Code != http.StatusOK || response.Body.Len() != 0 {
				t.Fatalf("HEAD: %d %q", response.Code, response.Body.String())
			}
			request := httptest.NewRequest(http.MethodGet, url, nil)
			request.Header.Set("If-None-Match", etag)
			response = httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusNotModified {
				t.Fatalf("revalidation: %d", response.Code)
			}
			for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions} {
				response = httptest.NewRecorder()
				handler.ServeHTTP(response, httptest.NewRequest(method, url, nil))
				if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != "GET, HEAD" {
					t.Fatalf("write method %s: %d", method, response.Code)
				}
			}
			for _, path := range []string{"", "../private.pem", ".private", nativePublicKey + "?token=x", "private.key", "repodata/", "pool/", "lindm-package-signing.gpg", "%2e%2e/private.pem"} {
				response = httptest.NewRecorder()
				handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://console.example/repo/"+family+"/"+path, nil))
				if response.Code != http.StatusNotFound {
					t.Fatalf("unsafe path %q: %d", path, response.Code)
				}
			}
		})
	}
}

func TestNativeRepositoryRejectsTamperingAndUnsafeFiles(t *testing.T) {
	for _, mutation := range []string{"wrong signer", "missing key", "signature", "metadata", "package", "symlink", "parent symlink", "fifo", "secret export", "appended secret", "replacement"} {
		t.Run(mutation, func(t *testing.T) {
			f := newNativeFixture(t)
			name := f.apt(t, "arm64")
			pin := f.fingerprint
			filename := filepath.Join(f.directory, "repo", "apt", filepath.FromSlash(name))
			loaded := loadNativeRepository(t.Context(), f.directory, "apt", pin)
			if loaded.err != nil {
				t.Fatal(loaded.err)
			}
			switch mutation {
			case "wrong signer":
				pin = strings.Repeat("0", 40)
			case "missing key":
				if err := os.Remove(filepath.Join(f.directory, "repo", "apt", nativePublicKey)); err != nil {
					t.Fatal(err)
				}
			case "signature":
				f.write(t, "apt", "dists/stable/Release.gpg", []byte("not a signature"))
			case "metadata":
				f.write(t, "apt", "dists/stable/main/binary-arm64/Packages", []byte("tampered"))
			case "package":
				f.write(t, "apt", name, []byte("tampered"))
			case "symlink":
				if err := os.Rename(filename, filename+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filename+".original", filename); err != nil {
					t.Fatal(err)
				}
			case "parent symlink":
				directory := filepath.Dir(filename)
				if err := os.Rename(directory, directory+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(directory+".original", directory); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := os.Remove(filename); err != nil {
					t.Fatal(err)
				}
				if err := unix.Mkfifo(filename, 0600); err != nil {
					t.Fatal(err)
				}
			case "secret export", "appended secret":
				var secret bytes.Buffer
				writer, err := armor.Encode(&secret, openpgp.PublicKeyType, nil)
				if err != nil {
					t.Fatal(err)
				}
				if err := f.key.SerializePrivate(writer, nil); err != nil {
					t.Fatal(err)
				}
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
				data := secret.Bytes()
				if mutation == "appended secret" {
					public, err := os.ReadFile(filepath.Join(f.directory, "repo", "apt", nativePublicKey))
					if err != nil {
						t.Fatal(err)
					}
					data = append(public, data...)
				}
				f.write(t, "apt", nativePublicKey, data)
			case "replacement":
				data, err := os.ReadFile(filename)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(filename, filename+".original"); err != nil {
					t.Fatal(err)
				}
				f.write(t, "apt", name, data)
				// StripPrefix passes a relative URL path to this handler.
				request := httptest.NewRequest(http.MethodGet, "/"+name, nil)
				request.URL.Path = name
				response := httptest.NewRecorder()
				loaded.ServeHTTP(response, request)
				if response.Code != http.StatusServiceUnavailable {
					t.Fatalf("replacement served by old snapshot: %d", response.Code)
				}
				return
			}
			repo := loadNativeRepository(t.Context(), f.directory, "apt", pin)
			if repo.err == nil {
				t.Fatal("unsafe repository admitted")
			}
			request := httptest.NewRequest(http.MethodGet, "/"+nativePublicKey, nil)
			request.URL.Path = nativePublicKey
			response := httptest.NewRecorder()
			repo.ServeHTTP(response, request)
			if response.Code != http.StatusNotFound {
				t.Fatal("unready repository leaked public or private material")
			}
		})
	}
}

func TestNativeRepositoryRejectsUnsignedMetadataForEveryFamily(t *testing.T) {
	f := newNativeFixture(t)
	f.apt(t, "arm64")
	f.rpm(t, "aarch64")
	f.arch(t)
	for family, name := range map[string]string{"apt": "dists/stable/InRelease", "rpm": "repodata/repomd.xml.asc", "arch": "lindm.db.sig"} {
		if err := os.Remove(filepath.Join(f.directory, "repo", family, name)); err != nil {
			t.Fatal(err)
		}
		if repo := loadNativeRepository(t.Context(), f.directory, family, f.fingerprint); repo.err == nil {
			t.Fatalf("%s admitted unsigned metadata", family)
		}
	}
}

func TestNativeRepositoryBoundsAndCancellation(t *testing.T) {
	f := newNativeFixture(t)
	name := f.apt(t, "arm64")
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if repo := loadNativeRepository(cancelled, f.directory, "apt", f.fingerprint); repo.err == nil {
		t.Fatal("cancelled startup continued admission")
	}
	file, err := os.OpenFile(filepath.Join(f.directory, "repo", "apt", name), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(nativePackageLimit + 1); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if repo := loadNativeRepository(t.Context(), f.directory, "apt", f.fingerprint); repo.err == nil {
		t.Fatal("oversized package admitted")
	}
}

func TestNativeRepositoryLoadsWhenOpenat2IsUnavailable(t *testing.T) {
	const child = "LINDM_NATIVE_OPENAT2_DENIED"
	mode := os.Getenv(child)
	if mode == "" {
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, binary, "-test.run=^TestNativeRepositoryLoadsWhenOpenat2IsUnavailable$")
		command.Env = append(os.Environ(), child+"=kernel")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("native repository sandbox subprocess: %v\n%s", err, output)
		}
		return
	}
	if mode != "kernel" && mode != "systemd" {
		t.Fatal("native repository syscall regression requires kernel or actual-systemd mode")
	}
	fixture := bundledNativeFixture(t, false)
	if mode == "kernel" {
		denyNativeOpenat2(t)
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, fixture.directory, &unix.OpenHow{Flags: unix.O_PATH | unix.O_DIRECTORY})
	if fd >= 0 {
		if closeErr := unix.Close(fd); closeErr != nil {
			t.Fatal(closeErr)
		}
	}
	if !errors.Is(err, unix.ENOSYS) {
		t.Fatalf("kernel did not refuse openat2 with ENOSYS: %v", err)
	}
	repositories := loadNativeBundle(t.Context(), fixture.directory)
	for index, repository := range []*nativeRepository{repositories.apt, repositories.rpm, repositories.arch} {
		if repository.err != nil {
			t.Fatalf("signed %s repository refused with openat2 unavailable: %v", [...]string{"apt", "rpm", "arch"}[index], repository.err)
		}
	}
}

func denyNativeOpenat2(t *testing.T) {
	t.Helper()
	// Scope irreversible seccomp to the fresh test subprocess, across its Go
	// threads. Match the kernel's openat2 refusal under RestrictSUIDSGID.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	filter := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(unix.SYS_OPENAT2), Jf: 1},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS)},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
	}
	program := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	result, _, errno := unix.Syscall6(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&program)), 0, 0, 0)
	runtime.KeepAlive(filter)
	runtime.KeepAlive(program)
	if errno != 0 || result != 0 {
		t.Fatalf("install native repository kernel-seccomp regression boundary: result=%d errno=%v", result, errno)
	}
}

func TestNativeRepositoryRefusesSymlinkAboveRepositoryRoot(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "real", "repository")
	if err := os.MkdirAll(directory, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "package.rpm"), []byte("signed fixture"), 0444); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "real"), filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	repository := &nativeRepository{directory: filepath.Join(root, "alias", "repository")}
	if file, err := repository.open("package.rpm"); err == nil {
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		t.Fatal("symlink in absolute ancestry above repository root was followed")
	}
}

func TestNativeRepositoryPinsOpenedFileAcrossAncestorReplacement(t *testing.T) {
	root := t.TempDir()
	directory, replacement := filepath.Join(root, "repository"), filepath.Join(root, "replacement")
	for path, contents := range map[string]string{directory: "original", replacement: "replacement"} {
		if err := os.Mkdir(path, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "package.rpm"), []byte(contents), 0444); err != nil {
			t.Fatal(err)
		}
	}
	repository := &nativeRepository{directory: directory}
	file, err := repository.open("package.rpm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := os.Rename(directory, directory+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(replacement, directory); err != nil {
		t.Fatal(err)
	}
	contents, err := io.ReadAll(file)
	if err != nil || string(contents) != "original" {
		t.Fatalf("opened native descriptor followed replacement: contents=%q err=%v", contents, err)
	}
	if next, err := repository.open("package.rpm"); err == nil {
		if err := next.Close(); err != nil {
			t.Fatal(err)
		}
		t.Fatal("subsequent native open followed replacement symlink")
	}
}
