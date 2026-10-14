// SPDX-License-Identifier: Apache-2.0

//go:build linux

package desktop

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// These tests use real temporary files and descriptor-only constructors. They
// do not claim native FileChooser qualification or relax production UID checks.
func transferTestPolicy(limit int64) TransferFilePolicy {
	return TransferFilePolicy{MaxBytes: limit, AllowType: func(mime, extension string) bool {
		return mime == "text/plain" && extension == ".txt"
	}}
}

func transferTestDirectory(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	// TempDir creates its returned child with 0777 before umask, so a 0002
	// umask leaves it group-writable. Model an owned private directory without
	// changing the process-wide umask or relaxing the production checks.
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func transferTestOpen(t *testing.T, path string) *os.File {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return file
}

func transferTestClose(t *testing.T, file *os.File) {
	t.Helper()
	if err := file.Close(); err != nil {
		t.Error(err)
	}
}

func transferTestIncoming(t *testing.T, ctx context.Context, dir, name string, size int64, policy TransferFilePolicy) *IncomingTransferFile {
	t.Helper()
	file, err := newIncomingTransferFileAt(ctx, transferTestOpen(t, dir), uint32(os.Getuid()), name, size, policy)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	})
	return file
}

func transferTestOutgoing(t *testing.T, ctx context.Context, path string, policy TransferFilePolicy) *OutgoingTransferFile {
	t.Helper()
	file, err := openTransferPath(path, unix.O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	out, err := newOutgoingTransferFile(ctx, file, policy)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := out.Close(); err != nil {
			t.Error(err)
		}
	})
	return out
}

func transferTestWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func transferTestEntries(t *testing.T, dir string, want int) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != want {
		t.Fatalf("directory has %d entries, want %d: %v", len(entries), want, entries)
	}
}

func transferTestClosedFD(t *testing.T, fd uintptr) {
	t.Helper()
	if _, err := unix.FcntlInt(fd, unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("owned descriptor not closed: %v", err)
	}
}

func TestTransferLocalURIValidation(t *testing.T) {
	for _, uri := range []string{
		"", "/tmp/data.txt", "file:/tmp/data.txt", "file://localhost/tmp/data.txt",
		"file://remote/tmp/data.txt", "https:///tmp/data.txt", "file:///", "file:///tmp/../data.txt",
		"file:///tmp/%2e%2e/data.txt", "file:///tmp//data.txt", "file:///tmp/data.txt/",
		"file:///tmp/data.txt?", "file:///tmp/data.txt#", "file:///tmp/data.txt?q=1",
		"file:///tmp/data.txt#part", "file:///tmp/%00data.txt", "file:///tmp/%ff.txt",
		"file:///tmp/%xx.txt", "file:///tmp/\x00data.txt", "file:///" + strings.Repeat("a", transferPathBytes),
	} {
		if _, err := chosenTransferPath(uri); !errors.Is(err, ErrTransferFileUnsafe) {
			t.Errorf("accepted unsafe URI %q: %v", uri, err)
		}
	}
	path, err := chosenTransferPath("file:///tmp/a%20b%23c%3Fd.txt")
	if err != nil || path != "/tmp/a b#c?d.txt" {
		t.Fatalf("escaped local URI = %q, %v", path, err)
	}
}

func TestTransferPathWalkRejectsSymlinksAndTraversal(t *testing.T) {
	dir := t.TempDir()
	child := filepath.Join(dir, "real")
	if err := os.Mkdir(child, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(child, "data.txt")
	transferTestWrite(t, path, []byte("selected"))
	if err := os.Symlink(child, filepath.Join(dir, "linked")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, filepath.Join(dir, "leaf.txt")); err != nil {
		t.Fatal(err)
	}
	for _, unsafe := range []string{filepath.Join(dir, "linked", "data.txt"), filepath.Join(dir, "leaf.txt"), dir + "/real/../real/data.txt", path + "/"} {
		file, err := openTransferPath(unsafe, unix.O_RDONLY)
		if file != nil {
			transferTestClose(t, file)
		}
		if err == nil {
			t.Errorf("followed unsafe path %q", unsafe)
		}
	}
	file, err := openTransferPath(path, unix.O_RDONLY)
	if err != nil {
		t.Fatal(err)
	}
	defer transferTestClose(t, file)
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
		t.Fatalf("selected file is not read-only: %v", err)
	}
	if file.Name() != "data.txt" {
		t.Fatalf("selected descriptor exposes a full path: %q", file.Name())
	}
}

func TestTransferChosenFileProductionUIDAndNonRegularBoundary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.txt")
	transferTestWrite(t, path, []byte("chosen"))
	uri := (&url.URL{Scheme: "file", Path: path}).String()
	file, err := openChosenTransferFile(uri)
	if os.Getuid() == 0 || os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() {
		if file != nil {
			transferTestClose(t, file)
		}
		if !errors.Is(err, ErrTransferFileUnsafe) {
			t.Fatalf("privileged chooser open = %v", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	transferTestClose(t, file)
	fifo := filepath.Join(dir, "fifo.txt")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dir, fifo} {
		file, err := openChosenTransferFile((&url.URL{Scheme: "file", Path: path}).String())
		if file != nil {
			transferTestClose(t, file)
		}
		if !errors.Is(err, ErrTransferFileUnsafe) {
			t.Fatalf("nonregular chooser open = %v", err)
		}
	}
}

func TestTransferDownloadsCreationOwnershipAndSymlinkBoundary(t *testing.T) {
	for _, kind := range []string{"absent", "existing", "symlink", "file", "writable", "wrong-owner", "unsafe-home"} {
		t.Run(kind, func(t *testing.T) {
			home := transferTestDirectory(t)
			path := filepath.Join(home, "Downloads")
			switch kind {
			case "existing", "writable", "wrong-owner":
				if err := os.Mkdir(path, 0755); err != nil {
					t.Fatal(err)
				}
				if kind == "writable" {
					if err := os.Chmod(path, 0777); err != nil {
						t.Fatal(err)
					}
				}
			case "symlink":
				if err := os.Symlink(transferTestDirectory(t), path); err != nil {
					t.Fatal(err)
				}
			case "file":
				transferTestWrite(t, path, []byte("untouched"))
			case "unsafe-home":
				if err := os.Chmod(home, 0777); err != nil {
					t.Fatal(err)
				}
			}
			uid := uint32(os.Getuid())
			if kind == "wrong-owner" {
				uid++
			}
			homeFD := transferTestOpen(t, home)
			defer transferTestClose(t, homeFD)
			downloads, err := openTransferDownloadsAt(homeFD, uid)
			if kind != "absent" && kind != "existing" {
				if downloads != nil {
					transferTestClose(t, downloads)
				}
				if err == nil {
					t.Fatal("accepted unsafe Downloads")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer transferTestClose(t, downloads)
			var stat unix.Stat_t
			if err := unix.Fstat(int(downloads.Fd()), &stat); err != nil {
				t.Fatal(err)
			}
			if stat.Uid != uid || stat.Mode&unix.S_IFMT != unix.S_IFDIR || (kind == "absent" && stat.Mode&0777 != 0700) {
				t.Fatalf("unsafe Downloads stat: %+v", stat)
			}
		})
	}
}

func TestIncomingTransferRejectsUnsafeNamesWithoutStaging(t *testing.T) {
	for _, name := range []string{"", ".", "..", ".hidden", "../escape.txt", "a/b.txt", "a\\b.txt", "/absolute.txt", "a:b.txt", "a\x00.txt", "a\n.txt", " a.txt", "a.txt ", "a.txt.", "a\u202etxt.exe", "a\u2028.txt", string([]byte{0xff}), strings.Repeat("a", 256)} {
		t.Run(name, func(t *testing.T) {
			dir := transferTestDirectory(t)
			fd := transferTestOpen(t, dir)
			number := fd.Fd()
			_, err := newIncomingTransferFileAt(t.Context(), fd, uint32(os.Getuid()), name, 1, transferTestPolicy(10))
			if !errors.Is(err, ErrTransferFileUnsafe) {
				t.Fatalf("unsafe basename = %v", err)
			}
			transferTestClosedFD(t, number)
			transferTestEntries(t, dir, 0)
		})
	}
}

func TestIncomingTransferHashSniffAndPrivatePublication(t *testing.T) {
	for _, data := range [][]byte{nil, []byte("hello\n"), bytes.Repeat([]byte("chunked text\n"), 9000)} {
		dir := transferTestDirectory(t)
		in := transferTestIncoming(t, t.Context(), dir, "Report.TXT", int64(len(data)), transferTestPolicy(256<<10))
		var staging unix.Stat_t
		if err := unix.Fstat(int(in.file.Fd()), &staging); err != nil {
			t.Fatal(err)
		}
		if staging.Mode&07777 != 0600 || staging.Nlink != 1 || staging.Uid != uint32(os.Getuid()) {
			t.Fatalf("unsafe staging stat: %+v", staging)
		}
		for offset := 0; offset < len(data); {
			end := min(offset+701, len(data))
			if n, err := in.Write(data[offset:end]); err != nil || n != end-offset {
				t.Fatalf("write = %d, %v", n, err)
			}
			offset = end
		}
		fileFD, dirFD := in.file.Fd(), in.dir.Fd()
		digest := sha256.Sum256(data)
		metadata, err := in.Publish(digest)
		if err != nil {
			t.Fatal(err)
		}
		if metadata.Size != int64(len(data)) || metadata.SHA256 != digest || metadata.MIME != "text/plain" {
			t.Fatalf("incorrect receiver metadata: %+v", metadata)
		}
		if !in.Published() {
			t.Fatal("successful rename not reported")
		}
		transferTestClosedFD(t, fileFD)
		transferTestClosedFD(t, dirFD)
		path := filepath.Join(dir, "Report.TXT")
		actual, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(actual, data) {
			t.Fatalf("published bytes differ: %v", err)
		}
		stat, err := os.Stat(path)
		if err != nil || stat.Mode().Perm() != 0600 {
			t.Fatalf("publication is not private and non-executable: %v, %v", stat, err)
		}
		transferTestEntries(t, dir, 1)
		if _, err := in.Write([]byte("late")); !errors.Is(err, ErrTransferFileClosed) {
			t.Fatalf("write after publication = %v", err)
		}
	}
}

func TestIncomingTransferNeverOverwritesExistingEntry(t *testing.T) {
	for _, kind := range []string{"file", "symlink", "directory"} {
		t.Run(kind, func(t *testing.T) {
			dir := transferTestDirectory(t)
			target := filepath.Join(t.TempDir(), "untouched.txt")
			transferTestWrite(t, target, []byte("untouched"))
			final := filepath.Join(dir, "data.txt")
			switch kind {
			case "file":
				transferTestWrite(t, final, []byte("existing"))
			case "symlink":
				if err := os.Symlink(target, final); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(final, 0700); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.Lstat(final)
			if err != nil {
				t.Fatal(err)
			}
			in := transferTestIncoming(t, t.Context(), dir, "data.txt", 3, transferTestPolicy(3))
			if _, err := in.Write([]byte("new")); err != nil {
				t.Fatal(err)
			}
			if _, err := in.Publish(sha256.Sum256([]byte("new"))); !errors.Is(err, unix.EEXIST) {
				t.Fatalf("overwrite attempt = %v", err)
			}
			after, err := os.Lstat(final)
			if err != nil || !os.SameFile(before, after) {
				t.Fatalf("existing entry changed: %v", err)
			}
			if data, err := os.ReadFile(target); err != nil || string(data) != "untouched" {
				t.Fatalf("symlink target changed: %q, %v", data, err)
			}
			if kind == "file" {
				if data, err := os.ReadFile(final); err != nil || string(data) != "existing" {
					t.Fatalf("existing bytes changed: %q, %v", data, err)
				}
			}
			transferTestEntries(t, dir, 1)
		})
	}
}

func TestIncomingTransferFailureAndCancellationCleanup(t *testing.T) {
	for _, kind := range []string{"short", "oversize", "chunk-bound", "hash", "mime", "extension", "cancel-write", "cancel-publish", "close"} {
		t.Run(kind, func(t *testing.T) {
			dir := transferTestDirectory(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			name, data, size := "data.txt", []byte("hello"), int64(5)
			if kind == "extension" {
				name = "data.exe"
			}
			if kind == "mime" {
				data = []byte("%PDF-")
			}
			if kind == "chunk-bound" {
				size = TransferFileChunkBytes + 1
				data = bytes.Repeat([]byte("x"), int(size))
			}
			in := transferTestIncoming(t, ctx, dir, name, size, transferTestPolicy(2*TransferFileChunkBytes))
			fileFD, dirFD := in.file.Fd(), in.dir.Fd()
			var err error
			want := ErrTransferFileSize
			switch kind {
			case "cancel-write":
				cancel()
				_, err = in.Write(data)
				want = context.Canceled
			case "oversize":
				_, err = in.Write([]byte("longer"))
			case "chunk-bound":
				_, err = in.Write(data)
			case "close":
				err = in.Close()
				want = nil
			default:
				if kind != "short" {
					if _, err := in.Write(data); err != nil {
						t.Fatal(err)
					}
				}
				digest := sha256.Sum256(data)
				switch kind {
				case "hash":
					digest[0] ^= 1
					want = ErrTransferFileHash
				case "mime", "extension":
					want = ErrTransferFileType
				case "cancel-publish":
					cancel()
					want = context.Canceled
				}
				_, err = in.Publish(digest)
			}
			if !errors.Is(err, want) {
				t.Fatalf("failure = %v, want %v", err, want)
			}
			if in.Published() {
				t.Fatal("failed transfer reported publication")
			}
			transferTestClosedFD(t, fileFD)
			transferTestClosedFD(t, dirFD)
			transferTestEntries(t, dir, 0)
			if err := in.Close(); err != nil {
				t.Fatalf("idempotent close = %v", err)
			}
		})
	}
}

func TestIncomingTransferRejectsInvalidBoundsAndPolicy(t *testing.T) {
	for _, tc := range []struct {
		size   int64
		policy TransferFilePolicy
		want   error
	}{
		{-1, transferTestPolicy(10), ErrTransferFileSize},
		{11, transferTestPolicy(10), ErrTransferFileSize},
		{0, transferTestPolicy(0), ErrTransferFileUnsafe},
		{0, TransferFilePolicy{MaxBytes: 10}, ErrTransferFileUnsafe},
	} {
		dir := transferTestDirectory(t)
		fd := transferTestOpen(t, dir)
		number := fd.Fd()
		_, err := newIncomingTransferFileAt(t.Context(), fd, uint32(os.Getuid()), "data.txt", tc.size, tc.policy)
		if !errors.Is(err, tc.want) {
			t.Fatalf("invalid bounds/policy = %v, want %v", err, tc.want)
		}
		transferTestClosedFD(t, number)
		transferTestEntries(t, dir, 0)
	}
}

func TestIncomingTransferFinalVerificationReadsRetainedBytes(t *testing.T) {
	for _, kind := range []string{"rewrite", "truncate", "executable", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := transferTestDirectory(t)
			in := transferTestIncoming(t, t.Context(), dir, "data.txt", 5, transferTestPolicy(5))
			if _, err := in.Write([]byte("hello")); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "rewrite":
				if _, err := in.file.WriteAt([]byte("other"), 0); err != nil {
					t.Fatal(err)
				}
			case "truncate":
				if err := in.file.Truncate(2); err != nil {
					t.Fatal(err)
				}
			case "executable":
				if err := in.file.Chmod(0700); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(filepath.Join(dir, in.staging), filepath.Join(dir, "other-link")); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := in.Publish(sha256.Sum256([]byte("hello"))); !errors.Is(err, ErrTransferFileChanged) {
				t.Fatalf("modified staging publication = %v", err)
			}
			wantEntries := 0
			if kind == "hardlink" {
				wantEntries = 1 // Cleanup must not remove an unrelated hardlink.
			}
			transferTestEntries(t, dir, wantEntries)
		})
	}
}

func TestIncomingTransferCleanupRefusesReplacedStaging(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		dir := transferTestDirectory(t)
		in := transferTestIncoming(t, t.Context(), dir, "data.txt", 0, transferTestPolicy(1))
		stage := filepath.Join(dir, in.staging)
		moved := filepath.Join(dir, "moved-by-user")
		if err := os.Rename(stage, moved); err != nil {
			t.Fatal(err)
		}
		if symlink {
			if err := os.Symlink(moved, stage); err != nil {
				t.Fatal(err)
			}
		} else {
			transferTestWrite(t, stage, []byte("replacement"))
		}
		before, err := os.Lstat(stage)
		if err != nil {
			t.Fatal(err)
		}
		if err := in.Close(); !errors.Is(err, ErrTransferFileChanged) {
			t.Fatalf("replacement cleanup = %v", err)
		}
		after, err := os.Lstat(stage)
		if err != nil || !os.SameFile(before, after) {
			t.Fatalf("cleanup deleted another file: %v", err)
		}
		transferTestEntries(t, dir, 2)
	}
}

func TestIncomingTransferRetainsDirectoryAcrossRename(t *testing.T) {
	for _, publish := range []bool{false, true} {
		home := transferTestDirectory(t)
		dir := filepath.Join(home, "Downloads")
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		in := transferTestIncoming(t, t.Context(), dir, "data.txt", 0, transferTestPolicy(1))
		moved := filepath.Join(home, "original-downloads")
		if err := os.Rename(dir, moved); err != nil {
			t.Fatal(err)
		}
		replacement := transferTestDirectory(t)
		if err := os.Symlink(replacement, dir); err != nil {
			t.Fatal(err)
		}
		if publish {
			if _, err := in.Publish(sha256.Sum256(nil)); err != nil {
				t.Fatal(err)
			}
			transferTestEntries(t, moved, 1)
		} else {
			if err := in.Close(); err != nil {
				t.Fatal(err)
			}
			transferTestEntries(t, moved, 0)
		}
		transferTestEntries(t, replacement, 0)
	}
}

func TestOutgoingTransferBoundedSniffReadHashAndOffset(t *testing.T) {
	for _, data := range [][]byte{nil, []byte("hello"), bytes.Repeat([]byte("bounded text\n"), 9000)} {
		path := filepath.Join(t.TempDir(), "Report.TXT")
		transferTestWrite(t, path, data)
		file := transferTestOpen(t, path)
		fd := file.Fd()
		if _, err := file.Seek(7, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		out, err := newOutgoingTransferFile(t.Context(), file, transferTestPolicy(256<<10))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := out.Close(); err != nil {
				t.Error(err)
			}
		})
		if offset, err := file.Seek(0, io.SeekCurrent); err != nil || offset != 7 {
			t.Fatalf("sniff changed descriptor offset: %d, %v", offset, err)
		}
		name, size, mime := out.Info()
		if name != "Report.TXT" || size != int64(len(data)) || mime != "text/plain" {
			t.Fatalf("initial metadata = %q, %d, %q", name, size, mime)
		}
		var got bytes.Buffer
		buffer := make([]byte, TransferFileChunkBytes+10)
		for {
			n, err := out.Read(buffer)
			if n > TransferFileChunkBytes {
				t.Fatalf("unbounded outgoing chunk: %d", n)
			}
			if _, writeErr := got.Write(buffer[:n]); writeErr != nil {
				t.Fatal(writeErr)
			}
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		if !bytes.Equal(got.Bytes(), data) {
			t.Fatal("outgoing bytes differ")
		}
		metadata, err := out.Finish()
		if err != nil || metadata.Size != int64(len(data)) || metadata.SHA256 != sha256.Sum256(data) || metadata.MIME != mime {
			t.Fatalf("outgoing completion = %+v, %v", metadata, err)
		}
		transferTestClosedFD(t, fd)
		if _, err := out.Read(buffer); !errors.Is(err, ErrTransferFileClosed) {
			t.Fatalf("read after Finish = %v", err)
		}
	}
}

func TestOutgoingTransferRejectsSizeTypeExtensionAndWritableFD(t *testing.T) {
	for _, kind := range []string{"size", "mime", "extension", "writable", "directory", "fifo", "policy", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "data.txt")
			data := []byte("hello")
			policy := transferTestPolicy(5)
			want := ErrTransferFileUnsafe
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch kind {
			case "size":
				policy.MaxBytes = 4
				want = ErrTransferFileSize
			case "mime":
				data = []byte("%PDF-")
				want = ErrTransferFileType
			case "extension":
				path = filepath.Join(filepath.Dir(path), "data.exe")
				want = ErrTransferFileType
			case "policy":
				policy.AllowType = nil
			case "cancelled":
				cancel()
				want = context.Canceled
			}
			flags := unix.O_RDONLY
			if kind == "writable" {
				flags = unix.O_RDWR
			}
			switch kind {
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := unix.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			default:
				transferTestWrite(t, path, data)
			}
			file, err := openTransferPath(path, flags)
			if err != nil {
				t.Fatal(err)
			}
			fd := file.Fd()
			_, err = newOutgoingTransferFile(ctx, file, policy)
			if !errors.Is(err, want) {
				t.Fatalf("outgoing adoption = %v, want %v", err, want)
			}
			transferTestClosedFD(t, fd)
		})
	}
}

func TestOutgoingTransferDetectsMutationTruncationAndIncompleteRead(t *testing.T) {
	for _, kind := range []string{"rewrite", "truncate", "grow", "mode", "after-eof", "incomplete", "cancel-read", "cancel-finish"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "data.txt")
			transferTestWrite(t, path, []byte("hello"))
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			out := transferTestOutgoing(t, ctx, path, transferTestPolicy(5))
			fd := out.file.Fd()
			var buf [10]byte
			want := ErrTransferFileChanged
			if kind == "after-eof" || kind == "cancel-finish" {
				if _, err := io.ReadFull(out, buf[:5]); err != nil {
					t.Fatal(err)
				}
				if _, err := out.Read(buf[:]); !errors.Is(err, io.EOF) {
					t.Fatalf("read beyond original size = %v", err)
				}
			}
			switch kind {
			case "rewrite", "after-eof":
				transferTestWrite(t, path, []byte("other"))
				// Force a different timestamp without sleeping or relying on clock
				// resolution; same-size data mutation must not report success.
				changed := time.Unix(1, 0)
				if err := os.Chtimes(path, changed, changed); err != nil {
					t.Fatal(err)
				}
			case "truncate":
				if err := os.Truncate(path, 2); err != nil {
					t.Fatal(err)
				}
			case "grow":
				if err := os.Truncate(path, 6); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := os.Chmod(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "incomplete":
				want = ErrTransferFileSize
			case "cancel-read", "cancel-finish":
				cancel()
				want = context.Canceled
			}
			var err error
			if kind == "after-eof" || kind == "incomplete" || kind == "cancel-finish" {
				_, err = out.Finish()
			} else {
				var n int
				n, err = out.Read(buf[:])
				if n != 0 {
					t.Fatalf("released bytes after mutation/cancellation: %d", n)
				}
			}
			if !errors.Is(err, want) {
				t.Fatalf("changed outgoing = %v, want %v", err, want)
			}
			transferTestClosedFD(t, fd)
		})
	}
}

func TestOutgoingTransferNeverReopensSelectedPath(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "selected")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "data.txt")
	transferTestWrite(t, path, []byte("original"))
	out := transferTestOutgoing(t, t.Context(), path, transferTestPolicy(8))
	if err := os.Rename(dir, filepath.Join(root, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	transferTestWrite(t, path, []byte("replaced"))
	var buf [8]byte
	if _, err := io.ReadFull(out, buf[:]); err != nil || string(buf[:]) != "original" {
		t.Fatalf("descriptor read reopened selected path: %q, %v", buf, err)
	}
	if _, err := out.Finish(); err != nil {
		t.Fatal(err)
	}
}

func TestTransferErrorsDoNotExposeLocalNames(t *testing.T) {
	pathErr := &os.PathError{Op: "read", Path: "/private/secret.txt", Err: unix.EIO}
	err := transferFileError(pathErr)
	if !errors.Is(err, unix.EIO) || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "private") {
		t.Fatalf("sensitive file error escaped: %v", err)
	}
}
