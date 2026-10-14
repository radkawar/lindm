// SPDX-License-Identifier: Apache-2.0

package labhost

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

const batchSecretBytes = 32

// ServeBatch reserves a complete host footprint atomically, then distributes
// each reserved flock descriptor at most once. The private credential routes and
// authenticates workers; possession alone never replaces an actual held flock.
// Cancellation closes the broker, but workers retain their inherited descriptors
// until their guests have exited, including if this process dies unexpectedly.
func (s *Slots) ServeBatch(ctx context.Context, guests uint32, admission time.Duration, report func(string), ready func(string) error) (err error) {
	if admission <= 0 {
		return errors.New("lab hosts: batch admission requires a positive deadline")
	}
	queue, cancel := context.WithTimeout(ctx, admission)
	leases, err := s.AcquireNReporting(queue, guests, report)
	cancel()
	if err != nil {
		return err
	}
	defer func() {
		for _, lease := range leases {
			err = errors.Join(err, lease.Close())
		}
	}()
	return serveBatchLeases(ctx, leases, ready)
}

func serveBatchLeases(ctx context.Context, leases []*Lease, ready func(string) error) (err error) {
	// A short private directory avoids sockaddr_un's path limit even when the
	// configured capacity namespace is deeply nested.
	directory, err := os.MkdirTemp("/tmp", "lindm-batch-")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, os.RemoveAll(directory)) }()
	path := filepath.Join(directory, "lease.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, closeBatchListener(listener)) }()
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	secret := make([]byte, batchSecretBytes, batchSecretBytes+len(path))
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	defer clear(secret)
	credential := base64.RawURLEncoding.EncodeToString(append(secret, path...))
	if err := ready(credential); err != nil {
		return err
	}
	connections := make([]*net.UnixConn, 0, len(leases))
	next := 0
	defer func() {
		for _, connection := range connections {
			err = errors.Join(err, connection.Close())
		}
	}()
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		var lease *Lease
		if next < len(leases) {
			lease = leases[next]
		}
		consumed, offerErr := offerBatchLease(ctx, connection, secret, lease)
		if consumed {
			next++ // A possibly transferred descriptor is never offered twice.
		}
		if offerErr != nil {
			if closeErr := connection.Close(); closeErr != nil {
				return errors.Join(offerErr, closeErr)
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			continue // Invalid credentials never consume a reservation.
		}
		connections = append(connections, connection)
	}
}

func closeBatchListener(listener *net.UnixListener) error {
	if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

func offerBatchLease(ctx context.Context, connection *net.UnixConn, secret []byte, lease *Lease) (consumed bool, err error) {
	stop := context.AfterFunc(ctx, func() { _ = connection.SetDeadline(time.Now()) })
	defer stop()
	if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return false, err
	}
	var supplied [batchSecretBytes]byte
	if _, err := io.ReadFull(connection, supplied[:]); err != nil {
		return false, err
	}
	if subtle.ConstantTimeCompare(supplied[:], secret) != 1 || lease == nil {
		return false, errors.New("lab hosts: invalid or exhausted batch reservation")
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.file == nil {
		return false, errors.New("lab hosts: batch lease closed")
	}
	if _, _, err := connection.WriteMsgUnix([]byte{1}, unix.UnixRights(int(lease.file.Fd())), nil); err != nil {
		return true, err
	}
	return true, connection.SetDeadline(time.Time{})
}

// RunBatchWorker receives and validates one actual reserved descriptor from a
// live broker. It cancels run if the broker disappears and holds the descriptor
// through run's complete teardown. It never acquires another capacity slot.
func (s *Slots) RunBatchWorker(ctx context.Context, credential string, run func(context.Context) error) (err error) {
	connection, lease, err := s.joinBatch(ctx, credential)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, lease.Close()) }()
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		_, readErr := io.Copy(io.Discard, connection)
		if readErr == nil {
			readErr = errors.New("lab hosts: batch reservation ended")
		}
		cancel(readErr)
	}()
	defer func() {
		err = errors.Join(err, connection.Close())
		<-stopped
	}()
	return run(ctx)
}

func (s *Slots) joinBatch(ctx context.Context, credential string) (*net.UnixConn, *Lease, error) {
	if len(credential) > 4096 {
		return nil, nil, errors.New("lab hosts: oversized batch credential")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(credential)
	if err != nil || len(decoded) <= batchSecretBytes || !filepath.IsAbs(string(decoded[batchSecretBytes:])) {
		return nil, nil, errors.New("lab hosts: invalid batch credential")
	}
	defer clear(decoded)
	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "unix", string(decoded[batchSecretBytes:]))
	if err != nil {
		return nil, nil, fmt.Errorf("lab hosts: connect batch reservation: %w", err)
	}
	connection, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, nil, errors.Join(errors.New("lab hosts: batch connection is not Unix"), conn.Close())
	}
	lease, err := s.receiveBatchLease(ctx, connection, decoded[:batchSecretBytes])
	if err != nil {
		return nil, nil, errors.Join(err, connection.Close())
	}
	return connection, lease, nil
}

func (s *Slots) receiveBatchLease(ctx context.Context, connection *net.UnixConn, secret []byte) (_ *Lease, err error) {
	stop := context.AfterFunc(ctx, func() { _ = connection.SetDeadline(time.Now()) })
	defer stop()
	if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return nil, err
	}
	if _, err := connection.Write(secret); err != nil {
		return nil, err
	}
	var response [1]byte
	rights := make([]byte, unix.CmsgSpace(4))
	n, oobn, flags, _, err := connection.ReadMsgUnix(response[:], rights)
	if err != nil {
		return nil, err
	}
	messages, err := unix.ParseSocketControlMessage(rights[:oobn])
	if err != nil {
		return nil, err
	}
	var descriptors []int
	for _, message := range messages {
		fds, err := unix.ParseUnixRights(&message)
		if err != nil {
			for _, fd := range descriptors {
				_ = unix.Close(fd)
			}
			return nil, err
		}
		descriptors = append(descriptors, fds...)
	}
	if n != 1 || response[0] != 1 || flags&unix.MSG_CTRUNC != 0 || len(descriptors) != 1 {
		for _, fd := range descriptors {
			_ = unix.Close(fd)
		}
		return nil, errors.New("lab hosts: batch did not transfer exactly one lease")
	}
	unix.CloseOnExec(descriptors[0])
	file := os.NewFile(uintptr(descriptors[0]), "batch-lease")
	if err := s.validateBatchLease(file); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		return nil, errors.Join(err, file.Close())
	}
	return &Lease{file: file}, nil
}

func (s *Slots) validateBatchLease(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	// Any slot identity of the namespace, including one beyond a lowered limit.
	indices, err := s.indices()
	if err != nil {
		return err
	}
	for _, index := range indices {
		candidate, err := s.open(index)
		if err != nil {
			return err
		}
		other, statErr := candidate.Stat()
		matches := statErr == nil && os.SameFile(info, other)
		if !matches {
			if err := errors.Join(statErr, candidate.Close()); err != nil {
				return err
			}
			continue
		}
		acquired, lockErr := lockSlot(candidate)
		closeErr := candidate.Close()
		if err := errors.Join(lockErr, closeErr); err != nil {
			return err
		}
		if acquired {
			return errors.New("lab hosts: transferred slot was not already reserved")
		}
		// An independently opened descriptor cannot take another description's
		// exclusive flock. Success proves SCM_RIGHTS carried the holder itself.
		if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
			return fmt.Errorf("lab hosts: descriptor does not hold the reserved flock: %w", err)
		}
		return nil
	}
	return errors.New("lab hosts: transferred lease belongs to another host namespace")
}

// ReadBatchCredential reads an owner-only handoff, never command-line authority.
func ReadBatchCredential(path string) (_ string, err error) {
	file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return "", err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0077 != 0 || stat.Uid != uint32(os.Geteuid()) || stat.Size <= 0 || stat.Size > 4096 {
		return "", errors.New("lab hosts: batch credential must be a bounded private owned regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil {
		return "", err
	}
	defer clear(data)
	if len(data) > 4096 {
		return "", errors.New("lab hosts: batch credential exceeds bound")
	}
	return string(data), nil
}
