// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"strings"

	"buf.build/go/protovalidate"
	"github.com/klauspost/compress/zstd"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
	"lindm/internal/platform"
)

const (
	redHatRecordBytes          = 128 << 20
	redHatArchiveExpandedBytes = 32 << 30
)

var errRedHatNotApplicable = errors.New("feed: Red Hat document has no configured host RHEL applicability")
var errRedHatNonNativeRPM = errors.New("feed: RPM purl is outside the native Red Hat namespace")
var errRedHatAmbiguousIdentity = errors.New("feed: conflicting Red Hat product or relationship identity")

type redHatProduct struct {
	product     suseProduct
	arch        string
	unsupported bool
	ambiguous   bool
	cpes        map[string]struct{}
}

type redHatRelationship struct {
	suseRelationship
	ambiguous bool
	platforms map[string]struct{}
}

type redHatRPM struct {
	name, version, arch, module, stream string
	source                              bool
}

// parseRedHat retains the bounded materialized API for callers and fixtures.
// Production publication uses the same parser with a disk-backed claim stager.
func parseRedHat(config *advisoryv1.FeedSource, raw []byte, validator protovalidate.Validator) (*advisoryv1.FeedDocument, error) {
	return collectBoundedClaims(func(emit func(*advisoryv1.Advisory) error) (*advisoryv1.FeedDocument, error) {
		return stageRedHatStream(context.Background(), config, validator, bytes.NewReader(raw), emit)
	})
}

func redHatConfig(config *advisoryv1.FeedSource) error {
	if config == nil {
		return errors.New("feed: Red Hat CSAF source required")
	}
	if _, err := vendorProduct(config, platform.FeedRedHatCSAF); err != nil {
		return err
	}
	parts := strings.Split(config.GetRelease(), ".")
	if len(parts) > 2 || !suseDigits(parts[0]) || (len(parts) == 2 && !suseDigits(parts[1])) {
		return errors.New("feed: invalid Red Hat release")
	}
	switch config.GetPlatformStream() {
	case "standard":
	case "eus", "e4s":
		if len(parts) != 2 {
			return errors.New("feed: extended Red Hat streams require exact major.minor")
		}
	default:
		return errors.New("feed: explicit Red Hat standard/eus/e4s stream required")
	}
	switch canonicalArch(config.GetArchitecture()) {
	case "x86_64", "aarch64", "ppc64le", "s390x", "i686":
		return nil
	default:
		return errors.New("feed: explicit supported Red Hat architecture required")
	}
}

// Legacy module relationships may insert a module between RPM and product.
// Follow only declared edges, with a depth bound also rejecting cycles.
func redHatPlatformProduct(id string, products map[string]redHatProduct, relations map[string]redHatRelationship, depth int) (suseProduct, string, error) {
	if depth > 8 {
		return suseProduct{}, "", errors.New("feed: cyclic Red Hat module relationship")
	}
	if p, ok := products[id]; ok {
		if p.ambiguous {
			return suseProduct{}, "", errRedHatAmbiguousIdentity
		}
		return p.product, "", nil
	}
	r, ok := relations[id]
	if !ok {
		return suseProduct{}, "", errors.New("feed: unresolved Red Hat platform")
	}
	if r.ambiguous {
		return suseProduct{}, "", errRedHatAmbiguousIdentity
	}
	p, module, err := redHatPlatformProduct(r.Platform, products, relations, depth+1)
	if err != nil {
		return p, "", err
	}
	component, ok := products[r.Component]
	if !ok || module != "" {
		return p, "", errors.New("feed: unsupported nested Red Hat module")
	}
	if component.ambiguous {
		return p, "", errRedHatAmbiguousIdentity
	}
	if r.Category != "default_component_of" || component.unsupported {
		return p, "", errors.New("feed: unsupported Red Hat module relationship constraint")
	}
	return p, component.product.ID, nil
}

func redHatPlatform(config *advisoryv1.FeedSource, product suseProduct, status string) (bool, bool) {
	cpe := strings.Split(product.Helper.CPE, ":")
	if len(cpe) < 5 || len(cpe) > 7 || (cpe[1] != "/o" && cpe[1] != "/a") || cpe[0] != "cpe" || cpe[2] != "redhat" {
		return false, false
	}
	if len(cpe) > 5 && cpe[5] != "" {
		return false, false
	}
	if len(cpe) == 7 && cpe[6] != "baseos" && cpe[6] != "appstream" && cpe[6] != "crb" && cpe[6] != "server" && cpe[6] != "workstation" && cpe[6] != "computenode" && cpe[6] != "client" {
		return false, false
	}
	release, stream := cpe[4], ""
	switch cpe[3] {
	case "enterprise_linux":
		stream = "standard"
	case "rhel_eus", "enterprise_linux_eus":
		stream = "eus"
	case "rhel_e4s", "enterprise_linux_e4s":
		stream = "e4s"
	default:
		return false, false
	}
	major, _, _ := strings.Cut(config.GetRelease(), ".")
	if release != config.GetRelease() && (stream != "standard" || strings.Contains(release, ".") || release != major) {
		return false, false
	}
	if stream == config.GetPlatformStream() {
		return true, false
	}
	// The legacy major-wide unfixed CPE is not proof of an EUS/E4S package
	// being vulnerable forever. Retain uncertainty until exact stream fixes
	// are reconciled; never transplant a mainstream fixed EVR into xUS.
	return stream == "standard" && status != "fixed", true
}

func redHatModule(value string) (string, string, error) {
	parts := strings.Split(value, ":")
	if (len(parts) != 2 && len(parts) != 4) || parts[0] == "" || parts[1] == "" || strings.ContainsAny(value, " /?&#\t\r\n") || (len(parts) == 4 && (parts[2] == "" || parts[3] == "")) {
		return "", "", errors.New("feed: invalid Red Hat module NS or NSVC")
	}
	return parts[0], parts[1], nil
}

func redHatPackage(component redHatProduct) (redHatRPM, error) {
	var pkg redHatRPM
	raw, rpm := strings.CutPrefix(component.product.Helper.PURL, "pkg:rpm/")
	if !rpm {
		return pkg, errRedHatNonNativeRPM
	}
	if strings.Contains(raw, "#") {
		return pkg, errors.New("feed: Red Hat RPM fragment unsupported")
	}
	identity, query, _ := strings.Cut(raw, "?")
	name, version, versioned := strings.Cut(identity, "@")
	separator := strings.LastIndexByte(name, '/')
	if separator < 1 {
		return pkg, errors.New("feed: RPM purl lacks namespace")
	}
	namespace, name := name[:separator], name[separator+1:]
	native := false
	for remaining := namespace; ; {
		segment, rest, more := strings.Cut(remaining, "/")
		decoded, err := url.PathUnescape(segment)
		if err != nil || decoded == "" || strings.ContainsAny(decoded, "%/:@?&# \t\r\n") {
			return pkg, errors.New("feed: invalid RPM purl namespace")
		}
		if remaining == namespace && !more {
			native = decoded == "redhat"
		}
		if !more {
			break
		}
		remaining = rest
	}
	// PURL names are path components: decode exactly once, without query
	// decoding's conversion of a literal '+' into a space. Display labels and
	// product IDs are opaque; neither supplies a second package identity.
	name, err := url.PathUnescape(name)
	if err != nil || name == "" || strings.ContainsAny(name, "%/@ :\t\n\r") {
		return pkg, fmt.Errorf("feed: invalid RPM name in Red Hat purl %q", redHatBoundedDiagnostic(component.product.Helper.PURL, 256))
	}
	q, err := url.ParseQuery(query)
	if err != nil {
		return pkg, errors.New("feed: invalid Red Hat RPM purl")
	}
	for key, values := range q {
		if len(values) != 1 || key == "" || (native && key != purlArch && key != "epoch" && key != "rpmmod" && key != "repository_id") {
			return pkg, errors.New("feed: unsupported Red Hat RPM qualifier")
		}
	}
	if !native {
		if versioned {
			decoded, err := url.PathUnescape(version)
			if err != nil || decoded == "" || strings.ContainsAny(decoded, "%/@?# \t\r\n") {
				return pkg, errors.New("feed: invalid RPM purl version")
			}
		}
		return pkg, errRedHatNonNativeRPM
	}
	pkg.name, pkg.arch = name, canonicalArch(q.Get(purlArch))
	pkg.source = pkg.arch == "src" || pkg.arch == "nosrc"
	if component.arch != "" && component.arch != pkg.arch {
		return pkg, errors.New("feed: conflicting Red Hat RPM architecture")
	}
	if value := q.Get("rpmmod"); value != "" {
		pkg.module, pkg.stream, err = redHatModule(value)
		if err != nil {
			return pkg, err
		}
	}
	if versioned {
		vr, err := url.PathUnescape(version)
		epoch := q.Get("epoch")
		if epoch == "" {
			epoch = "0"
		}
		if err != nil || !suseDigits(epoch) || !strings.Contains(vr, "-") || pkg.arch == "" {
			return pkg, errors.New("feed: invalid Red Hat RPM EVR")
		}
		pkg.version = epoch + ":" + vr
	} else if q.Has("epoch") {
		return pkg, errors.New("feed: unversioned Red Hat RPM has epoch")
	}
	return pkg, nil
}

// parseRedHatArchive is the bounded collector for an authenticated archive.
func parseRedHatArchive(ctx context.Context, config *advisoryv1.FeedSource, input io.Reader, validator protovalidate.Validator) (doc *advisoryv1.FeedDocument, err error) {
	if err := redHatConfig(config); err != nil {
		return nil, err
	}
	stager, err := newRedHatStager(ctx, config)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, stager.close())
		if err != nil {
			doc = nil
		}
	}()
	if err := parseRedHatArchiveStream(ctx, config, input, validator, stager.add); err != nil {
		return nil, err
	}
	return collectBoundedClaims(func(emit func(*advisoryv1.Advisory) error) (*advisoryv1.FeedDocument, error) {
		if err := stager.emit(ctx, emit); err != nil {
			return nil, err
		}
		return &advisoryv1.FeedDocument{}, nil
	})
}

// parseRedHatArchiveStream consumes only already authenticated original bytes.
// Each JSON entry is staged separately; the source stager reconciles all entries
// and both distributions before any callback may publish normalized claims.
func parseRedHatArchiveStream(ctx context.Context, config *advisoryv1.FeedSource, input io.Reader, validator protovalidate.Validator, emit func(*advisoryv1.Advisory) error) error {
	return parseRedHatArchiveEach(ctx, config, input, func(entry io.Reader) error {
		return parseRedHatClaims(ctx, config, entry, validator, emit)
	})
}

func parseRedHatArchiveEach(ctx context.Context, config *advisoryv1.FeedSource, input io.Reader, consume func(io.Reader) error) error {
	return parseRedHatArchiveNamed(ctx, config, input, func(entry io.Reader, _ string) error {
		return consume(entry)
	})
}

func parseRedHatArchiveNamed(ctx context.Context, config *advisoryv1.FeedSource, input io.Reader, consume func(io.Reader, string) error) error {
	if err := redHatConfig(config); err != nil {
		return err
	}
	decoder, err := zstd.NewReader(contextFeedReader{ctx, input}, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(maxExpandedBytes))
	if err != nil {
		return fmt.Errorf("feed: open Red Hat archive: %w", err)
	}
	defer decoder.Close()
	limited := &io.LimitedReader{R: decoder, N: redHatArchiveExpandedBytes + 1}
	archive := tar.NewReader(limited)
	for entries := 0; ; entries++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("feed: read Red Hat archive: %w", err)
		}
		if entries >= maxEntries || limited.N <= 0 {
			return errors.New("feed: Red Hat archive expansion or entry limit")
		}
		if header.Typeflag == tar.TypeDir {
			continue
		}
		if header.Typeflag != tar.TypeReg || !strings.HasSuffix(header.Name, ".json") || header.Size < 0 || header.Size > redHatRecordBytes || strings.HasPrefix(header.Name, "/") || strings.Contains(header.Name, "\\") || strings.Contains(header.Name, "../") {
			return errors.New("feed: unsupported Red Hat archive entry")
		}
		err = consume(archive, header.Name)
		if errors.Is(err, errRedHatNotApplicable) {
			continue
		}
		if err != nil {
			return fmt.Errorf("feed: Red Hat archive entry %s: %w", path.Base(header.Name), err)
		}
	}
	return finishRedHatArchive(limited)
}

// Consume the zstd trailer as well: tar EOF alone does not authenticate the
// compressed frame checksum or bound trailing decompressed padding. One byte
// beyond the configured expansion budget distinguishes exact-bound from overflow.
func finishRedHatArchive(limited *io.LimitedReader) error {
	if _, err := io.Copy(io.Discard, limited); err != nil {
		return fmt.Errorf("feed: finish Red Hat compressed archive: %w", err)
	}
	if limited.N <= 0 {
		return errors.New("feed: Red Hat archive expansion limit")
	}
	return nil
}
