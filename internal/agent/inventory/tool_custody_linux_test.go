//go:build linux

package inventory

import (
	"context"
	"io/fs"
	"os"
	"syscall"
	"testing"
	"time"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

type custodyInfo struct {
	mode fs.FileMode
	stat syscall.Stat_t
}

func (i custodyInfo) Name() string       { return "" }
func (i custodyInfo) Size() int64        { return 0 }
func (i custodyInfo) Mode() fs.FileMode  { return i.mode }
func (i custodyInfo) ModTime() time.Time { return time.Time{} }
func (i custodyInfo) IsDir() bool        { return i.mode.IsDir() }
func (i custodyInfo) Sys() any           { return &i.stat }

func custodyStat(dirs map[string][2]uint32) func(string) (fs.FileInfo, error) {
	return func(path string) (fs.FileInfo, error) {
		d, ok := dirs[path]
		if !ok {
			return nil, &fs.PathError{Op: "stat", Path: path, Err: fs.ErrNotExist}
		}
		return custodyInfo{mode: fs.ModeDir | fs.FileMode(d[1]), stat: syscall.Stat_t{Uid: d[0], Mode: syscall.S_IFDIR | d[1]}}, nil
	}
}

func TestToolCustodyNamesTheFirstUnprotectedAncestor(t *testing.T) {
	protected := map[string][2]uint32{"/": {0, 0o555}, "/usr": {0, 0o755}, "/usr/bin": {0, 0o755}, "/usr/sbin": {0, 0o755}}
	for _, tc := range []struct {
		name   string
		change map[string][2]uint32
		want   *inventoryv1.NativeToolCustody
	}{
		// /usr/libexec is absent: no tool resolves through it.
		{"protected", nil, &inventoryv1.NativeToolCustody{Status: success}},
		// Fedora Cloud Base 43-1.6 ships / as root:root 0775.
		{"group-writable root", map[string][2]uint32{"/": {0, 0o775}}, &inventoryv1.NativeToolCustody{Status: success, UnprotectedPath: "/", Mode: 0o775}},
		{"foreign owner", map[string][2]uint32{"/usr/bin": {1000, 0o755}}, &inventoryv1.NativeToolCustody{Status: success, UnprotectedPath: "/usr/bin", OwnerUid: 1000, Mode: 0o755}},
		{"other-writable sticky", map[string][2]uint32{"/usr/sbin": {0, 0o1777}}, &inventoryv1.NativeToolCustody{Status: success, UnprotectedPath: "/usr/sbin", Mode: 0o1777}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dirs := map[string][2]uint32{}
			for path, d := range protected {
				dirs[path] = d
			}
			for path, d := range tc.change {
				dirs[path] = d
			}
			got := collectToolCustody(context.Background(), detailSources{stat: custodyStat(dirs)})
			if got.GetStatus() != tc.want.GetStatus() || got.GetUnprotectedPath() != tc.want.GetUnprotectedPath() || got.GetOwnerUid() != tc.want.GetOwnerUid() || got.GetMode() != tc.want.GetMode() {
				t.Fatalf("custody = %v, want %v", got, tc.want)
			}
		})
	}
}

// / and /usr always exist on a supported host; their absence is not success.
func TestToolCustodyRequiresRootAndUsr(t *testing.T) {
	got := collectToolCustody(context.Background(), detailSources{stat: custodyStat(map[string][2]uint32{"/": {0, 0o555}})})
	if got.GetStatus() != inventoryv1.CollectionStatus_COLLECTION_STATUS_UNAVAILABLE || got.GetUnprotectedPath() != "" {
		t.Fatalf("custody without /usr = %v", got)
	}
}

// The real host this test runs on reports its own ancestry through os.Stat.
func TestToolCustodyObservesTheHost(t *testing.T) {
	got := collectToolCustody(context.Background(), detailSources{stat: os.Stat})
	if got.GetStatus() != success {
		t.Fatalf("host custody status = %v", got.GetStatus())
	}
}
