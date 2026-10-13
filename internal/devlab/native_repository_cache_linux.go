//go:build linux

package devlab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
	"golang.org/x/sys/unix"

	releasev1 "lindm/gen/lindm/release/v1"
	"lindm/internal/packaging"
	"lindm/internal/releasebuild"
)

const nativeFixtureBuildBudget = time.Hour

type nativeRepositoryBuild func(context.Context, string, string, string) (*releasev1.ReleaseManifest, error)

type cachedNativeRepository struct {
	directory   string
	manifest    *releasev1.ReleaseManifest
	fingerprint string
	hit         bool
}

// PrepareNativeEnrollmentRepository completes the cold signed artifact build
// before a browser review starts its own deadline. The cache contains only
// authenticated, complete development releases, never private signing custody.
func PrepareNativeEnrollmentRepository(ctx context.Context, repository, sourceRepository string) error {
	_, err := cachedNativeEnrollmentRepository(ctx, sourceRepository, nativeRepositoryCacheDirectory(repository), buildDevelopmentNativeRepository)
	return err
}

func nativeRepositoryCacheDirectory(repository string) string {
	return filepath.Join(repository, ".cache", "lab", "agent-repositories")
}

func cachedNativeEnrollmentRepository(ctx context.Context, source, cache string, build nativeRepositoryBuild) (_ *cachedNativeRepository, resultErr error) {
	if err := ensureNativeRepositoryCache(cache); err != nil {
		return nil, err
	}
	sourceDigest, err := releasebuild.SourceDigest(ctx, source)
	if err != nil {
		return nil, err
	}
	key := sha256.Sum256([]byte(fmt.Sprintf("stock-agent-v1\x00%s\x000.1.0\x00console-enrollment-lab\x00%d", sourceDigest, packaging.DefaultSourceDateEpoch)))
	entry := filepath.Join(cache, hex.EncodeToString(key[:]))
	lock, err := lockAcceptanceFeedCache(ctx, entry+".lock")
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, lock.Close()) }()
	if _, err := os.Lstat(entry); err == nil {
		result, err := loadCachedNativeRepository(ctx, entry, sourceDigest)
		if err != nil {
			return nil, fmt.Errorf("cached stock agent artifact %q failed verification; remove this cache entry before rebuilding: %w", entry, err)
		}
		result.hit = true
		return result, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	work, err := os.MkdirTemp(cache, ".build-")
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, os.RemoveAll(work)) }()
	bundle := filepath.Join(work, "agent-repository")
	buildCtx, cancel := context.WithTimeout(ctx, nativeFixtureBuildBudget)
	defer cancel()
	manifest, err := build(buildCtx, source, bundle, filepath.Join(work, "custody"))
	if err != nil {
		return nil, fmt.Errorf("build signed stock artifact: %w", err)
	}
	if manifest.GetSourceSha256() != sourceDigest {
		return nil, errors.New("stock agent source changed during the build; no cache entry was published")
	}
	result, err := loadCachedNativeRepository(buildCtx, bundle, sourceDigest)
	if err != nil {
		return nil, err
	}
	if err := os.Rename(bundle, entry); err != nil {
		return nil, err
	}
	result.directory = entry
	return result, nil
}

func ensureNativeRepositoryCache(directory string) error {
	if err := os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode().Perm()&0077 != 0 || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("stock agent cache must be an owned private directory, not a link or shared directory")
	}
	return nil
}

func buildDevelopmentNativeRepository(ctx context.Context, source, bundle, custody string) (manifest *releasev1.ReleaseManifest, resultErr error) {
	if err := os.Mkdir(custody, 0700); err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, os.RemoveAll(custody)) }()
	signer, err := packaging.GenerateDevelopmentSigner(ctx, custody)
	if err != nil {
		return nil, err
	}
	attestation := filepath.Join(custody, "attestation")
	id, err := releasebuild.GenerateDevelopmentKey(attestation)
	if err != nil {
		return nil, err
	}
	return releasebuild.BuildDevelopmentAgentRepository(ctx, releasebuild.Request{
		Repository: source, Output: bundle, Version: "0.1.0", Revision: "console-enrollment-lab",
		SourceDateEpoch: packaging.DefaultSourceDateEpoch, PackageSigner: *signer,
		AttestationSigner: releasebuild.AttestationKey{Path: filepath.Join(attestation, "attestation.pem"), KeyID: id, Custody: "development"},
	})
}

func loadCachedNativeRepository(ctx context.Context, directory, sourceDigest string) (*cachedNativeRepository, error) {
	if err := checkNativeRepositoryCacheFiles(directory); err != nil {
		return nil, err
	}
	public, err := os.ReadFile(filepath.Join(directory, "attestation.pub"))
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(public)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("stock cache has invalid attestation public material")
	}
	if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		return nil, err
	}
	id := sha256.Sum256(block.Bytes)
	manifest, err := releasebuild.Verify(ctx, directory, filepath.Join(directory, "attestation.pub"), hex.EncodeToString(id[:]))
	if err != nil {
		return nil, err
	}
	if manifest.GetSourceSha256() != sourceDigest || manifest.GetVersion() != "0.1.0" || manifest.GetRevision() != "console-enrollment-lab" || manifest.GetSourceDateEpoch() != packaging.DefaultSourceDateEpoch || manifest.GetCustody() != "development" {
		return nil, errors.New("stock cache does not match the requested development release and source")
	}
	public, err = os.ReadFile(filepath.Join(directory, "package-signing.asc"))
	if err != nil {
		return nil, err
	}
	keys, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(public))
	if err != nil || len(keys) != 1 || keys[0].PrivateKey != nil {
		return nil, errors.New("stock cache has invalid native public signer")
	}
	return &cachedNativeRepository{directory: directory, manifest: manifest, fingerprint: strings.ToUpper(hex.EncodeToString(keys[0].PrimaryKey.Fingerprint))}, nil
}

func checkNativeRepositoryCacheFiles(directory string) error {
	count := 0
	return filepath.Walk(directory, func(name string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		count++
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || count > 512 || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0022 != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return fmt.Errorf("stock cache path %q is not a protected owned artifact", name)
		}
		if info.IsDir() {
			return nil
		}
		limit := int64(16 << 20)
		if strings.HasSuffix(name, ".deb") || strings.HasSuffix(name, ".rpm") || strings.HasSuffix(name, ".pkg.tar.zst") {
			limit = 1 << 30
		}
		if info.Size() <= 0 || info.Size() > limit {
			return fmt.Errorf("stock cache member %q exceeds its bounds", name)
		}
		return nil
	})
}

// Prefer copy-on-write clones, not hardlinks: linking a second fixture changes
// ctime and would correctly invalidate the first daemon's immutable snapshot.
func materializeNativeRepository(ctx context.Context, source, destination string) error {
	return filepath.WalkDir(source, func(name string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		rel, err := filepath.Rel(source, name)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, rel)
		if entry.IsDir() {
			return os.Mkdir(target, 0755)
		}
		return copyNativeRepositoryFile(name, target)
	})
}

func copyNativeRepositoryFile(source, destination string) (resultErr error) {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, input.Close()) }()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0444)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, output.Close()) }()
	cloneErr := unix.IoctlFileClone(int(output.Fd()), int(input.Fd()))
	if cloneErr == nil {
		return output.Sync()
	}
	if !errors.Is(cloneErr, unix.EXDEV) && !errors.Is(cloneErr, unix.EOPNOTSUPP) && !errors.Is(cloneErr, unix.ENOTTY) && !errors.Is(cloneErr, unix.EINVAL) {
		return cloneErr
	}
	if err := output.Truncate(0); err != nil {
		return err
	}
	count, err := io.Copy(output, io.LimitReader(input, (1<<30)+1))
	if err != nil {
		return err
	}
	if count > 1<<30 {
		return errors.New("stock cache copy exceeds native package bound")
	}
	return output.Sync()
}
