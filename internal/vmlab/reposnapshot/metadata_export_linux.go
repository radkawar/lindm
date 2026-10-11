//go:build linux

package reposnapshot

import (
	"context"
	"errors"
	"io"
	"slices"
	"strings"

	"google.golang.org/protobuf/proto"

	labv1 "lindm/gen/lindm/lab/v1"
)

// ExportMetadata authenticates the exact pinned repository metadata and invokes
// visit only for its finite signed metadata/key set, in path order. Every reader
// is an immutable verified payload; no RPM, evidence or arbitrary directory
// member is exported. The callback must finish consuming a reader before return.
// Missing retained metadata may be acquired from the pinned vendor source, but
// signature, signed date/digest and byte ceilings are never relaxed.
func ExportMetadata(ctx context.Context, options CaptureOptions, visit func(*labv1.RepositorySnapshotFile, io.Reader) error) (err error) {
	if visit == nil {
		return errors.New("metadata export callback is required")
	}
	if options.MaxBytes == 0 || options.MaxBytes > 512<<20 {
		options.MaxBytes = 512 << 20
	}
	options.SeedManifestSHA256 = ""
	options.SeedCache = ""
	capture, err := NewCapture(ctx, options)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, capture.Close()) }()
	files := slices.Clone(capture.Manifest.Files)
	slices.SortFunc(files, func(a, b *labv1.RepositorySnapshotFile) int { return strings.Compare(a.Path, b.Path) })
	if len(files) > 256 {
		return errors.New("retained metadata count exceeds bound")
	}
	for _, item := range files {
		if (!strings.HasPrefix(item.Path, "repodata/") && capture.keyPins[item.Path] == "") || strings.HasSuffix(item.Path, ".rpm") {
			return errors.New("metadata export refuses nonmetadata content")
		}
		payload, err := verifiedSnapshotPayload(ctx, capture.payloadRoot, capture.spool, item)
		if err != nil {
			return err
		}
		visitErr := visit(proto.CloneOf(item), payload)
		closeErr := payload.Close()
		if visitErr != nil || closeErr != nil {
			return errors.Join(visitErr, closeErr)
		}
	}
	return nil
}
