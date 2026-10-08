package spool

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"

	"lindm/internal/agent/statefs"
)

const (
	databaseName     = "spool.sqlite"
	collectionsName  = "collections"
	applicationID    = 1397776204 // "SPOL"
	userVersion      = 1
	pageSize         = 4096
	maxPageCount     = 2048
	journalSizeLimit = 4 << 20
	// Block slack for batch files and their directories stays inside the
	// 160 MiB physical budget together with the 16 MiB SQLite cap below.
	collectionPhysicalBudget = CollectionBudget + MaxBatches*4096
	sqlitePhysicalBudget     = 16 << 20
	slotPending              = 1
	slotQueued               = 2
	maxHostBytes             = 65536
)

func (s *Store) checkFile(name string) (bool, error) {
	exists, err := statefs.CheckFile(int(s.dir.Fd()), name)
	if errors.Is(err, statefs.ErrUnsafe) {
		return false, ErrUnsafe
	}
	return exists, err
}

func listDir(fd int) ([]string, error) {
	if _, err := unix.Seek(fd, 0, io.SeekStart); err != nil {
		return nil, err
	}
	buf := make([]byte, 8192)
	var names []string
	for {
		n, err := unix.ReadDirent(fd, buf)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return names, nil
		}
		consumed, _, next := unix.ParseDirent(buf[:n], -1, names)
		if consumed != n {
			return nil, ErrUnsafe
		}
		names = next
	}
}

func (s *Store) rootNames() ([]string, error) {
	return listDir(int(s.dir.Fd()))
}

func (s *Store) chmodName(name string, mode uint32) error {
	fd, err := unix.Openat(int(s.dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	return unix.Fchmod(fd, mode)
}

func (s *Store) chmodSidecars() error {
	for _, name := range []string{databaseName, databaseName + "-wal", databaseName + "-shm"} {
		if err := s.chmodName(name, 0600); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) createEmpty(name string) error {
	fd, err := unix.Openat(int(s.dir.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "spool-file")
	defer func() { _ = file.Close() }()
	return file.Sync()
}

func (s *Store) removeSQLiteFiles() error {
	for _, name := range []string{databaseName, databaseName + "-wal", databaseName + "-shm", databaseName + "-journal"} {
		err := unix.Unlinkat(int(s.dir.Fd()), name, 0)
		if err != nil && !errors.Is(err, unix.ENOENT) {
			return err
		}
	}
	return s.dir.Sync()
}

func (s *Store) fileBlocks(dirfd int, name string) (int64, error) {
	var st unix.Stat_t
	if err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return 0, nil
		}
		return 0, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return 0, ErrUnsafe
	}
	return int64(st.Blocks) * 512, nil
}

func (s *Store) sqlitePhysical() (int64, error) {
	return s.sumRootBlocks(databaseName, databaseName+"-wal", databaseName+"-shm", databaseName+"-journal")
}

func (s *Store) metadataPhysical() (int64, error) {
	sqliteBytes, err := s.sqlitePhysical()
	if err != nil {
		return 0, err
	}
	status, err := s.transportStatusPhysical()
	if err != nil {
		return 0, err
	}
	var root, collections unix.Stat_t
	if err := unix.Fstat(int(s.dir.Fd()), &root); err != nil {
		return 0, err
	}
	if err := unix.Fstatat(int(s.dir.Fd()), collectionsName, &collections, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if !errors.Is(err, unix.ENOENT) {
			return 0, err
		}
	} else if collections.Mode&unix.S_IFMT != unix.S_IFDIR {
		return 0, ErrUnsafe
	}
	return sqliteBytes + status + (root.Blocks+collections.Blocks)*512, nil
}

const (
	transportStatusName       = "transport-status.pb"
	transportStatusTempPrefix = ".transport-status-"
	maxTransportStatusBytes   = 16 << 10
)

func isTransportTemp(name string) bool {
	if len(name) <= len(transportStatusTempPrefix) || len(name) > 128 || !strings.HasPrefix(name, transportStatusTempPrefix) {
		return false
	}
	return !strings.ContainsAny(name, "/\\\x00")
}

func (s *Store) sumRootBlocks(names ...string) (int64, error) {
	var total int64
	for _, name := range names {
		n, err := s.fileBlocks(int(s.dir.Fd()), name)
		if err != nil {
			return 0, err
		}
		total += n
	}
	return total, nil
}

func (s *Store) transportStatusPhysical() (int64, error) {
	names, err := s.rootNames()
	if err != nil {
		return 0, err
	}
	var total int64
	for _, name := range names {
		if name != transportStatusName && !isTransportTemp(name) {
			continue
		}
		n, err := s.fileBlocks(int(s.dir.Fd()), name)
		if err != nil {
			return 0, err
		}
		total += n
	}
	return total, nil
}

func (s *Store) checkTransportStatus() error {
	var st unix.Stat_t
	err := unix.Fstatat(int(s.dir.Fd()), transportStatusName, &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0600 || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) || st.Size < 0 || st.Size > maxTransportStatusBytes {
		return ErrUnrecognized
	}
	return nil
}

func (s *Store) removeTransportTemp(name string) error {
	if !isTransportTemp(name) {
		return ErrUnrecognized
	}
	var st unix.Stat_t
	if err := unix.Fstatat(int(s.dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0600 || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) || st.Size < 0 || st.Size > maxTransportStatusBytes {
		return ErrUnrecognized
	}
	if err := unix.Unlinkat(int(s.dir.Fd()), name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	return nil
}

func canonicalUUID(id string) bool {
	parsed, err := uuid.Parse(id)
	return err == nil && parsed != uuid.Nil && parsed.String() == id
}

func batchFileName(index int) (string, bool) {
	if index < 0 || index >= MaxBatches {
		return "", false
	}
	return "b" + leftPad3(index), true
}

func leftPad3(n int) string {
	out := []byte{'0', '0', '0'}
	for i := 2; i >= 0 && n > 0; i-- {
		out[i] = byte('0' + n%10)
		n /= 10
	}
	if n != 0 {
		return ""
	}
	return string(out)
}

func parseBatchName(name string) (int, bool) {
	if len(name) != 4 || name[0] != 'b' {
		return 0, false
	}
	n := 0
	for _, c := range name[1:] {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	expect, ok := batchFileName(n)
	if !ok || expect != name {
		return 0, false
	}
	return n, true
}

func (s *Store) ensureCollections() error {
	err := unix.Mkdirat(int(s.dir.Fd()), collectionsName, 0700)
	if err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	fd, err := s.collectionsFD()
	if err != nil {
		return err
	}
	_ = unix.Close(fd)
	return s.dir.Sync()
}

func (s *Store) collectionsFD() (int, error) {
	fd, err := unix.Openat(int(s.dir.Fd()), collectionsName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	if st.Uid != uint32(os.Geteuid()) || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&07777 != 0700 {
		_ = unix.Close(fd)
		return -1, ErrUnsafe
	}
	return fd, nil
}

func (s *Store) collectionNames() ([]string, error) {
	fd, err := s.collectionsFD()
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(fd) }()
	return listDir(fd)
}

func writeExclusive(dirfd int, name string, data []byte) error {
	fd, err := unix.Openat(dirfd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "spool-batch")
	defer func() { _ = file.Close() }()
	if _, err := file.Write(data); err != nil {
		return err
	}
	return file.Sync()
}

func hashFile(dirfd int, name string) ([32]byte, int64, error) {
	var st unix.Stat_t
	if err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return [32]byte{}, 0, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0600 || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) || st.Size <= 0 || st.Size > MaxBatchEncoded {
		return [32]byte{}, 0, ErrUnsafe
	}
	fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return [32]byte{}, 0, err
	}
	file := os.NewFile(uintptr(fd), "spool-batch")
	defer func() { _ = file.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(file, MaxBatchEncoded+1))
	if err != nil {
		return [32]byte{}, 0, err
	}
	if n != st.Size {
		return [32]byte{}, 0, ErrUnsafe
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum, n, nil
}

func digestEqual(got []byte, want [32]byte) bool {
	return len(got) == len(want) && subtle.ConstantTimeCompare(got, want[:]) == 1
}

func (s *Store) openCollection(id string) (int, error) {
	if !canonicalUUID(id) {
		return -1, ErrUnsafe
	}
	parent, err := s.collectionsFD()
	if err != nil {
		return -1, err
	}
	defer func() { _ = unix.Close(parent) }()
	fd, err := unix.Openat(parent, id, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	if st.Uid != uint32(os.Geteuid()) || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&07777 != 0700 {
		_ = unix.Close(fd)
		return -1, ErrUnsafe
	}
	return fd, nil
}

// deleteCollection removes one tracked directory. It refuses symlinks, unexpected
// names, hardlinks and entries outside the 64 MiB / 512-file bound, and it never
// unlinks a path outside this spool directory.
func (s *Store) deleteCollection(id string) error {
	if !canonicalUUID(id) {
		return ErrUnrecognized
	}
	parent, err := s.collectionsFD()
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parent) }()
	fd, err := unix.Openat(parent, id, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Uid != uint32(os.Geteuid()) || st.Mode&07777 != 0700 {
		return ErrUnrecognized
	}
	names, err := listDir(fd)
	if err != nil {
		return err
	}
	if len(names) > MaxBatches {
		return ErrUnrecognized
	}
	var physical int64
	for _, name := range names {
		if _, ok := parseBatchName(name); !ok {
			return ErrUnrecognized
		}
		var info unix.Stat_t
		if err := unix.Fstatat(fd, name, &info, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		if info.Mode&unix.S_IFMT != unix.S_IFREG || info.Mode&07777 != 0600 || info.Nlink != 1 || info.Uid != uint32(os.Geteuid()) || info.Size < 0 || info.Size > MaxBatchEncoded {
			return ErrUnrecognized
		}
		physical += int64(info.Blocks) * 512
		if physical > collectionPhysicalBudget {
			return ErrUnrecognized
		}
	}
	for _, name := range names {
		if err := unix.Unlinkat(fd, name, 0); err != nil {
			return err
		}
	}
	if err := unix.Fsync(fd); err != nil {
		return err
	}
	if err := unix.Unlinkat(parent, id, unix.AT_REMOVEDIR); err != nil {
		return err
	}
	if err := unix.Fsync(parent); err != nil {
		return err
	}
	return s.dir.Sync()
}

func (s *Store) collectionPhysical(id string) (int64, error) {
	fd, err := s.openCollection(id)
	if errors.Is(err, unix.ENOENT) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer func() { _ = unix.Close(fd) }()
	names, err := listDir(fd)
	if err != nil {
		return 0, err
	}
	var total int64
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return 0, err
	}
	total += int64(st.Blocks) * 512
	for _, name := range names {
		n, err := s.fileBlocks(fd, name)
		if err != nil {
			return 0, err
		}
		total += n
	}
	return total, nil
}
