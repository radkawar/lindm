// SPDX-License-Identifier: Apache-2.0

//go:build linux

package desktop

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const (
	TransferFileChunkBytes = 64 << 10
	transferPathBytes      = 4096
	transferSniffBytes     = 512
)

var (
	ErrTransferFileUnsafe  = errors.New("desktop: transfer_file_unsafe")
	ErrTransferFileSize    = errors.New("desktop: transfer_file_size")
	ErrTransferFileChanged = errors.New("desktop: transfer_file_changed")
	ErrTransferFileHash    = errors.New("desktop: transfer_file_hash")
	ErrTransferFileType    = errors.New("desktop: transfer_file_type")
	ErrTransferFileClosed  = errors.New("desktop: transfer_file_closed")
)

// TransferFilePolicy is a local enforcement hook, not a wire schema or authority
// grant. The session supplies its authorized size ceiling and mandatory combined
// MIME/extension allowlist. MIME is the canonical base media type, without
// parameters. Extensions are lower-case and include the leading dot (or are
// empty). AllowType must be side-effect-free and must not reenter this object.
// MIME sniffing is not malware detection or complete format proof.
type TransferFilePolicy struct {
	MaxBytes  int64
	AllowType func(mime, extension string) bool
}

// TransferFileMetadata describes locally observed bytes, never a sender's type
// assertion. It deliberately contains neither a path nor a filename.
type TransferFileMetadata struct {
	Size   int64
	SHA256 [sha256.Size]byte
	MIME   string
}

func (p TransferFilePolicy) valid() bool { return p.MaxBytes > 0 && p.AllowType != nil }

func currentTransferUID() (uint32, error) {
	uid := os.Getuid()
	if uid <= 0 || uid != os.Geteuid() || os.Getgid() != os.Getegid() {
		return 0, ErrTransferFileUnsafe
	}
	return uint32(uid), nil
}

// transferFileError strips os.PathError names before errors cross the session
// boundary. Neither selected URIs, account homes nor filenames belong in logs.
func transferFileError(err error) error {
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err
	}
	return err
}

func validTransferPath(path string) bool {
	return len(path) <= transferPathBytes && path != "/" && filepath.IsAbs(path) &&
		filepath.Clean(path) == path && utf8.ValidString(path) && !strings.ContainsRune(path, 0)
}

// openTransferPath follows the native custody component-walk pattern, without
// its root-only ownership policy. Every open is relative to a held descriptor;
// a symlink in any component fails. Ancestor replacement never redirects a
// subsequent component through a replacement pathname.
func openTransferPath(path string, flags int) (_ *os.File, err error) {
	if !validTransferPath(path) {
		return nil, ErrTransferFileUnsafe
	}
	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil && fd >= 0 {
			err = errors.Join(err, unix.Close(fd))
		}
	}()
	parts := strings.Split(path[1:], "/")
	for i, part := range parts {
		mode := unix.O_PATH | unix.O_DIRECTORY
		if i == len(parts)-1 {
			mode = flags
		}
		next, openErr := unix.Openat(fd, part, mode|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		closeErr := unix.Close(fd)
		fd = next
		if openErr != nil {
			fd = -1
			return nil, errors.Join(openErr, closeErr)
		}
		if closeErr != nil {
			return nil, closeErr
		}
	}
	return os.NewFile(uintptr(fd), filepath.Base(path)), nil
}

func chosenTransferPath(uri string) (string, error) {
	if len(uri) > 3*transferPathBytes+7 || !strings.HasPrefix(uri, "file:///") || strings.ContainsAny(uri, "?#\x00") {
		return "", ErrTransferFileUnsafe
	}
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "file" || u.Host != "" || u.User != nil || u.Opaque != "" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || !validTransferPath(u.Path) {
		return "", ErrTransferFileUnsafe
	}
	return u.Path, nil
}

// openChosenTransferFile accepts only the exact URI authenticated by ChooseFile;
// never call it with an operator-selected path. The host portal returns a URI,
// not an inode-bound capability: replacement before this immediate no-follow
// open cannot be detected. All subsequent operations retain this descriptor.
func openChosenTransferFile(uri string) (_ *os.File, err error) {
	if _, err := currentTransferUID(); err != nil {
		return nil, err
	}
	path, err := chosenTransferPath(uri)
	if err != nil {
		return nil, err
	}
	if !validTransferBasename(filepath.Base(path)) {
		return nil, ErrTransferFileUnsafe
	}
	file, err := openTransferPath(path, unix.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, transferFileError(file.Close()))
		}
	}()
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Size < 0 {
		return nil, ErrTransferFileUnsafe
	}
	return file, nil
}

func openTransferDownloads() (_ *os.File, err error) {
	uid, err := currentTransferUID()
	if err != nil {
		return nil, err
	}
	account, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return nil, ErrTransferFileUnsafe
	}
	if account.Uid != strconv.FormatUint(uint64(uid), 10) {
		return nil, ErrTransferFileUnsafe
	}
	home, err := openTransferPath(account.HomeDir, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return nil, err
	}
	downloads, openErr := openTransferDownloadsAt(home, uid)
	closeErr := transferFileError(home.Close())
	if openErr != nil || closeErr != nil {
		if downloads != nil {
			closeErr = errors.Join(closeErr, transferFileError(downloads.Close()))
		}
		return nil, errors.Join(openErr, closeErr)
	}
	return downloads, nil
}

// openTransferDownloadsAt is the descriptor-only test seam. Production obtains
// home from the current nonroot UID's account record, never HOME or XDG variables.
func openTransferDownloadsAt(home *os.File, uid uint32) (_ *os.File, err error) {
	if err := checkTransferDirectory(home, uid); err != nil {
		return nil, err
	}
	created := false
	if err := unix.Mkdirat(int(home.Fd()), "Downloads", 0700); err == nil {
		created = true
	} else if !errors.Is(err, unix.EEXIST) {
		return nil, err
	}
	fd, err := unix.Openat(int(home.Fd()), "Downloads", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), "transfer-downloads")
	defer func() {
		if err != nil {
			err = errors.Join(err, transferFileError(dir.Close()))
		}
	}()
	if err := checkTransferDirectory(dir, uid); err != nil {
		return nil, err
	}
	if created {
		if err := home.Sync(); err != nil {
			return nil, transferFileError(err)
		}
	}
	return dir, nil
}

func checkTransferDirectory(dir *os.File, uid uint32) error {
	var stat unix.Stat_t
	if err := unix.Fstat(int(dir.Fd()), &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != uid || stat.Mode&0022 != 0 {
		return ErrTransferFileUnsafe
	}
	return nil
}

// validTransferBasename rejects rather than silently transforming an operator's
// name. Hidden files, separators, controls, bidi/format characters and trailing
// dots/spaces cannot disguise the final destination or create desktop dotfiles.
func validTransferBasename(name string) bool {
	if name == "" || len(name) > 255 || !utf8.ValidString(name) || strings.HasPrefix(name, ".") ||
		strings.TrimSpace(name) != name || strings.HasSuffix(name, ".") || strings.ContainsAny(name, "/\\:") {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
			return false
		}
	}
	return true
}

// IncomingTransferFile holds the original Downloads descriptor until commit or
// cleanup. Its 0600 exclusive staging file is never executable or auto-opened.
// Methods serialize cancellation with filesystem operations; callers must Close
// on every abandoned session. A cancelled context is checked at every chunk and
// before publication; this object does not start background goroutines.
//
// The account user can modify their own Downloads and files; this is not a
// sandbox against that same UID. Identity checks refuse observed staging-name
// substitution rather than deleting another file, but do not promise an atomic
// compare-and-unlink against a hostile process with the identical credentials.
type IncomingTransferFile struct {
	mu        sync.Mutex
	ctx       context.Context
	dir       *os.File
	file      *os.File
	identity  unix.Stat_t
	uid       uint32
	staging   string
	name      string
	expected  int64
	policy    TransferFilePolicy
	bytes     int64
	digest    hash.Hash
	prefix    [transferSniffBytes]byte
	prefixN   int
	closed    bool
	published bool
}

// NewIncomingTransferFile accepts a basename, not a path, and the declared size.
// The session must first authorize the transfer and supply its local policy.
func NewIncomingTransferFile(ctx context.Context, name string, size int64, policy TransferFilePolicy) (*IncomingTransferFile, error) {
	if err := validateIncomingTransfer(ctx, name, size, policy); err != nil {
		return nil, err
	}
	dir, err := openTransferDownloads()
	if err != nil {
		return nil, err
	}
	return newIncomingTransferFileAt(ctx, dir, uint32(os.Getuid()), name, size, policy)
}

func validateIncomingTransfer(ctx context.Context, name string, size int64, policy TransferFilePolicy) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validTransferBasename(name) || !policy.valid() {
		return ErrTransferFileUnsafe
	}
	if size < 0 || size > policy.MaxBytes {
		return ErrTransferFileSize
	}
	return nil
}

// newIncomingTransferFileAt takes ownership of dir, including on failure.
func newIncomingTransferFileAt(ctx context.Context, dir *os.File, uid uint32, name string, size int64, policy TransferFilePolicy) (_ *IncomingTransferFile, err error) {
	t := &IncomingTransferFile{ctx: ctx, dir: dir, uid: uid, name: name, expected: size, policy: policy, digest: sha256.New()}
	defer func() {
		if err != nil {
			err = errors.Join(err, t.closeLocked())
		}
	}()
	if err := validateIncomingTransfer(ctx, name, size, policy); err != nil {
		return nil, err
	}
	if err := checkTransferDirectory(dir, uid); err != nil {
		return nil, err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	staging := ".lindm-transfer-" + hex.EncodeToString(nonce[:])
	fd, err := unix.Openat(int(dir.Fd()), staging, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	t.staging = staging
	t.file = os.NewFile(uintptr(fd), "transfer-staging")
	if err := unix.Fstat(fd, &t.identity); err != nil {
		return nil, err
	}
	// Set the exact mode even with a restrictive umask or inherited default ACL.
	if err := unix.Fchmod(fd, 0600); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *IncomingTransferFile) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return 0, ErrTransferFileClosed
	}
	if err := t.ctx.Err(); err != nil {
		return 0, errors.Join(err, t.closeLocked())
	}
	if len(p) > TransferFileChunkBytes || int64(len(p)) > t.expected-t.bytes {
		return 0, errors.Join(ErrTransferFileSize, t.closeLocked())
	}
	n, err := t.file.Write(p)
	if n > 0 {
		_, _ = t.digest.Write(p[:n]) // crypto/sha256.Write never fails.
		t.prefixN += copy(t.prefix[t.prefixN:], p[:n])
		t.bytes += int64(n)
	}
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return n, errors.Join(transferFileError(err), t.closeLocked())
	}
	return n, nil
}

// Publish verifies both the received stream and the actual staged bytes before
// fsync and RENAME_NOREPLACE. Success includes checked file/directory closes and
// directory fsync. If rename succeeded but fsync/close failed, the error is an
// uncertain publication: the final file is retained, never rolled back by path.
func (t *IncomingTransferFile) Publish(expectedSHA256 [sha256.Size]byte) (_ TransferFileMetadata, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return TransferFileMetadata{}, ErrTransferFileClosed
	}
	defer func() { err = errors.Join(err, t.closeLocked()) }()
	if err := t.ctx.Err(); err != nil {
		return TransferFileMetadata{}, err
	}
	if t.bytes != t.expected {
		return TransferFileMetadata{}, ErrTransferFileSize
	}
	var digest [sha256.Size]byte
	t.digest.Sum(digest[:0])
	if digest != expectedSHA256 {
		return TransferFileMetadata{}, ErrTransferFileHash
	}
	mediaType, _, err := mime.ParseMediaType(http.DetectContentType(t.prefix[:t.prefixN]))
	if err != nil || !t.policy.AllowType(mediaType, strings.ToLower(filepath.Ext(t.name))) {
		return TransferFileMetadata{}, ErrTransferFileType
	}
	if err := t.verifyStaging(digest); err != nil {
		return TransferFileMetadata{}, err
	}
	if err := t.file.Sync(); err != nil {
		return TransferFileMetadata{}, transferFileError(err)
	}
	if err := checkTransferDirectory(t.dir, t.uid); err != nil {
		return TransferFileMetadata{}, err
	}
	var final unix.Stat_t
	if err := unix.Fstatat(int(t.dir.Fd()), t.staging, &final, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return TransferFileMetadata{}, err
	}
	if !sameTransferStat(t.identity, final) {
		return TransferFileMetadata{}, ErrTransferFileChanged
	}
	if err := t.ctx.Err(); err != nil {
		return TransferFileMetadata{}, err
	}
	if err := unix.Renameat2(int(t.dir.Fd()), t.staging, int(t.dir.Fd()), t.name, unix.RENAME_NOREPLACE); err != nil {
		return TransferFileMetadata{}, err
	}
	t.published = true
	t.staging = ""
	metadata := TransferFileMetadata{Size: t.bytes, SHA256: digest, MIME: mediaType}
	return metadata, transferFileError(t.dir.Sync())
}

func (t *IncomingTransferFile) verifyStaging(expected [sha256.Size]byte) error {
	var before unix.Stat_t
	if err := unix.Fstat(int(t.file.Fd()), &before); err != nil {
		return err
	}
	if before.Dev != t.identity.Dev || before.Ino != t.identity.Ino || before.Uid != t.uid ||
		before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&07777 != 0600 || before.Nlink != 1 || before.Size != t.bytes {
		return ErrTransferFileChanged
	}
	h := sha256.New()
	var buf [TransferFileChunkBytes]byte
	for offset := int64(0); offset < t.bytes; {
		if err := t.ctx.Err(); err != nil {
			return err
		}
		want := min(int64(len(buf)), t.bytes-offset)
		n, err := t.file.ReadAt(buf[:want], offset)
		if err != nil || int64(n) != want {
			return errors.Join(ErrTransferFileChanged, transferFileError(err))
		}
		_, _ = h.Write(buf[:n])
		offset += int64(n)
	}
	var actual [sha256.Size]byte
	h.Sum(actual[:0])
	var after unix.Stat_t
	if err := unix.Fstat(int(t.file.Fd()), &after); err != nil {
		return err
	}
	if actual != expected || !sameTransferStat(before, after) {
		return ErrTransferFileChanged
	}
	t.identity = after
	return nil
}

func (t *IncomingTransferFile) stagingIdentity() error {
	var stat unix.Stat_t
	if err := unix.Fstatat(int(t.dir.Fd()), t.staging, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if stat.Dev != t.identity.Dev || stat.Ino != t.identity.Ino || stat.Uid != t.uid || stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return ErrTransferFileChanged
	}
	return nil
}

// Published reports whether the no-replace rename occurred, even if subsequent
// directory fsync or close failed. True plus a Publish error is an unconfirmed
// durable outcome, not permission to retry or delete the published file.
func (t *IncomingTransferFile) Published() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.published
}

// Close cancels an unfinished transfer and unlinks only its still-owned staging
// name. It is idempotent; callers must check its first error, including cleanup.
func (t *IncomingTransferFile) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closeLocked()
}

func (t *IncomingTransferFile) closeLocked() error {
	if t.closed {
		return nil
	}
	t.closed = true
	var err error
	if t.staging != "" {
		identityErr := t.stagingIdentity()
		if identityErr == nil {
			err = unix.Unlinkat(int(t.dir.Fd()), t.staging, 0)
			if err == nil {
				err = transferFileError(t.dir.Sync())
			}
		} else if !errors.Is(identityErr, unix.ENOENT) {
			err = identityErr
		}
	}
	if t.file != nil {
		err = errors.Join(err, transferFileError(t.file.Close()))
		t.file = nil
	}
	if t.dir != nil {
		err = errors.Join(err, transferFileError(t.dir.Close()))
		t.dir = nil
	}
	return err
}

func sameTransferStat(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid &&
		a.Size == b.Size && a.Nlink == b.Nlink && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

// OutgoingTransferFile streams only the retained chooser descriptor. EOF is not
// success: Finish must succeed before sending a successful completion to the
// receiver. No reopen by path, whole-file copy or privileged read lease is used.
// Stat checks detect observed mutations; they do not freeze an inode against a
// same-UID writer or guarantee detection on filesystems with coarse timestamps.
type OutgoingTransferFile struct {
	mu       sync.Mutex
	ctx      context.Context
	file     *os.File
	identity unix.Stat_t
	bytes    int64
	digest   hash.Hash
	mime     string
	name     string
	closed   bool
}

// NewOutgoingTransferFile takes ownership of the exact ChooseFile descriptor,
// including on failure. A raw pathname or a reopened descriptor is not authority.
// Type and size policy are enforced before any bytes are returned to transport.
func NewOutgoingTransferFile(ctx context.Context, chosen *os.File, policy TransferFilePolicy) (*OutgoingTransferFile, error) {
	if _, err := currentTransferUID(); err != nil {
		if chosen != nil {
			err = errors.Join(err, transferFileError(chosen.Close()))
		}
		return nil, err
	}
	return newOutgoingTransferFile(ctx, chosen, policy)
}

func newOutgoingTransferFile(ctx context.Context, chosen *os.File, policy TransferFilePolicy) (_ *OutgoingTransferFile, err error) {
	t := &OutgoingTransferFile{ctx: ctx, file: chosen, digest: sha256.New()}
	defer func() {
		if err != nil {
			err = errors.Join(err, t.closeLocked())
		}
	}()
	if chosen == nil || !policy.valid() {
		return nil, ErrTransferFileUnsafe
	}
	t.name = filepath.Base(chosen.Name())
	if !validTransferBasename(t.name) {
		return nil, ErrTransferFileUnsafe
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	flags, err := unix.FcntlInt(chosen.Fd(), unix.F_GETFL, 0)
	if err != nil {
		return nil, err
	}
	if flags&unix.O_ACCMODE != unix.O_RDONLY || flags&unix.O_PATH != 0 {
		return nil, ErrTransferFileUnsafe
	}
	if err := unix.Fstat(int(chosen.Fd()), &t.identity); err != nil {
		return nil, err
	}
	if t.identity.Mode&unix.S_IFMT != unix.S_IFREG || t.identity.Nlink == 0 {
		return nil, ErrTransferFileUnsafe
	}
	if t.identity.Size < 0 || t.identity.Size > policy.MaxBytes {
		return nil, ErrTransferFileSize
	}
	var prefix [transferSniffBytes]byte
	want := min(int64(len(prefix)), t.identity.Size)
	n, err := chosen.ReadAt(prefix[:want], 0)
	if err != nil || int64(n) != want {
		return nil, errors.Join(ErrTransferFileChanged, transferFileError(err))
	}
	t.mime, _, err = mime.ParseMediaType(http.DetectContentType(prefix[:n]))
	if err != nil || !policy.AllowType(t.mime, strings.ToLower(filepath.Ext(t.name))) {
		return nil, ErrTransferFileType
	}
	if err := t.unchanged(); err != nil {
		return nil, err
	}
	return t, nil
}

// Info returns the approved safe basename, original size and sniffed MIME for
// Ready, before streaming. SHA-256 is available only after a successful Finish.
// These fields are immutable and disclose no parent directory.
func (t *OutgoingTransferFile) Info() (name string, size int64, mime string) {
	return t.name, t.identity.Size, t.mime
}

func (t *OutgoingTransferFile) unchanged() error {
	var stat unix.Stat_t
	if err := unix.Fstat(int(t.file.Fd()), &stat); err != nil {
		return err
	}
	if !sameTransferStat(t.identity, stat) {
		return ErrTransferFileChanged
	}
	return nil
}

func (t *OutgoingTransferFile) Read(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return 0, ErrTransferFileClosed
	}
	if err := t.ctx.Err(); err != nil {
		return 0, errors.Join(err, t.closeLocked())
	}
	if err := t.unchanged(); err != nil {
		return 0, errors.Join(err, t.closeLocked())
	}
	if len(p) == 0 {
		return 0, nil
	}
	if t.bytes == t.identity.Size {
		return 0, io.EOF
	}
	want := min(int64(len(p)), int64(TransferFileChunkBytes), t.identity.Size-t.bytes)
	n, err := t.file.ReadAt(p[:want], t.bytes)
	if err != nil || int64(n) != want {
		return 0, errors.Join(ErrTransferFileChanged, transferFileError(err), t.closeLocked())
	}
	if err := t.unchanged(); err != nil {
		return 0, errors.Join(err, t.closeLocked())
	}
	_, _ = t.digest.Write(p[:n])
	t.bytes += int64(n)
	return n, nil
}

// Finish verifies the entire declared size was read and the retained inode did
// not change, and closes it before reporting success. Call Close instead on an
// interrupted transfer. The caller must still require the receiver's digest.
func (t *OutgoingTransferFile) Finish() (_ TransferFileMetadata, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return TransferFileMetadata{}, ErrTransferFileClosed
	}
	defer func() { err = errors.Join(err, t.closeLocked()) }()
	if err := t.ctx.Err(); err != nil {
		return TransferFileMetadata{}, err
	}
	if t.bytes != t.identity.Size {
		return TransferFileMetadata{}, ErrTransferFileSize
	}
	if err := t.unchanged(); err != nil {
		return TransferFileMetadata{}, err
	}
	metadata := TransferFileMetadata{Size: t.bytes, MIME: t.mime}
	t.digest.Sum(metadata.SHA256[:0])
	return metadata, nil
}

func (t *OutgoingTransferFile) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closeLocked()
}

func (t *OutgoingTransferFile) closeLocked() error {
	if t.closed {
		return nil
	}
	t.closed = true
	if t.file == nil {
		return nil
	}
	err := transferFileError(t.file.Close())
	t.file = nil
	return err
}
