package labhost

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	labv1 "lindm/gen/lindm/lab/v1"
)

// Slots is a local process-shared capacity pool. All users of a work directory
// must use the same host name and capacity; change these only while it is idle.
// Lock files are permanent identities: never remove them to release a slot.
// For SSH hosts, OpenSlots, Count and Acquire must run on the remote host using
// the same staged binary. This type never interprets SSH transport as local work.
type Slots struct {
	directory   string
	capacity    uint32
	memoryMib   uint32
	memoryProbe func(context.Context) (memoryAdmission, error)
}

// OpenSlots opens the executing host's capacity namespace without taking a slot.
// The private namespace prevents other host users from replacing lock files.
func OpenSlots(host *labv1.LabHost) (*Slots, error) {
	work, err := ResolveWorkDirectory(host)
	if err != nil {
		return nil, err
	}
	directory := filepath.Join(work, ".leases", host.Name)
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, fmt.Errorf("lab hosts: create slots: %w", err)
	}
	for _, private := range []string{filepath.Join(work, ".leases"), directory} {
		var status unix.Stat_t
		if err := unix.Lstat(private, &status); err != nil {
			return nil, fmt.Errorf("lab hosts: inspect slot owner: %w", err)
		}
		if status.Mode&unix.S_IFMT != unix.S_IFDIR || status.Mode&0077 != 0 {
			return nil, fmt.Errorf("lab hosts: slot directory must be private: %s", private)
		}
		if status.Uid != uint32(os.Geteuid()) {
			return nil, fmt.Errorf("lab hosts: slot directory is not owned by this user: %s", private)
		}
	}
	return &Slots{directory: directory, capacity: host.MaxGuests, memoryMib: host.MaxMemoryMib, memoryProbe: observeMemory}, nil
}

func (s *Slots) open(index uint32) (*os.File, error) {
	return s.openName(fmt.Sprintf("slot-%04d.lock", index))
}

func (s *Slots) openName(name string) (*os.File, error) {
	filename := filepath.Join(s.directory, name)
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if err != nil {
		return nil, fmt.Errorf("lab hosts: open slot: %w", err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return nil, errors.Join(fmt.Errorf("lab hosts: inspect slot: %w", err), file.Close())
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0077 != 0 || stat.Nlink != 1 {
		return nil, errors.Join(errors.New("lab hosts: slot must be a private owned regular file with one link"), file.Close())
	}
	return file, nil
}

func lockSlot(file *os.File) (bool, error) {
	err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("lab hosts: lock slot: %w", err)
	}
	return true, nil
}

// Count counts held kernel locks, not files or PID markers. It is an observational
// snapshot, not a reservation; concurrent acquisitions can change it immediately.
func (s *Slots) Count() (uint32, error) {
	var count uint32
	indices, err := s.indices()
	if err != nil {
		return 0, err
	}
	for _, index := range indices {
		file, err := s.open(index)
		if err != nil {
			return 0, err
		}
		locked, lockErr := lockSlot(file)
		if err := errors.Join(lockErr, file.Close()); err != nil {
			return 0, err
		}
		if !locked {
			count++
		}
	}
	return count, nil
}

// Acquire waits for one slot until ctx is canceled. The caller owns the returned
// lease and must keep it until all guests and helpers have exited and been waited
// for. Pass a timeout/deadline context when admission must have a fixed time bound.
func (s *Slots) Acquire(ctx context.Context) (*Lease, error) {
	leases, err := s.AcquireN(ctx, 1)
	if err != nil {
		return nil, err
	}
	return leases[0], nil
}

// AcquireN waits until all guests of one lane are admitted together, holding
// no slot while it waits; a lane never owns part of its capacity.
func (s *Slots) AcquireN(ctx context.Context, guests uint32) ([]*Lease, error) {
	return s.AcquireNReporting(ctx, guests, nil)
}

// AcquireNReporting is AcquireN that calls report, when non-nil, each time the
// reason admission is waiting changes. Waiters are admitted in arrival order.
func (s *Slots) AcquireNReporting(ctx context.Context, guests uint32, report func(reason string)) (admitted []*Lease, resultErr error) {
	ticket, leave, err := s.queue(guests)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := leave(); err != nil {
			for _, lease := range admitted {
				err = errors.Join(err, lease.Close())
			}
			admitted, resultErr = nil, errors.Join(resultErr, err)
		}
	}()
	var last string
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		leases, wait, err := s.tryAcquireN(ctx, guests, ticket)
		if err != nil || leases != nil {
			return leases, err
		}
		if report != nil && wait != last && wait != admissionBusy {
			report(wait)
			last = wait
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

// LaneTiming bounds the two phases of a scheduled lane separately. Queue time
// never consumes the lane's own budget: a lane admitted after a long wait still
// gets its full Lane timeout. Zero Lane means no lane deadline (held lanes).
type LaneTiming struct {
	Admission, Lane time.Duration
}

// RunAdmitted waits, in FIFO order and for at most timing.Admission, until all
// guests are admitted, then runs the lane under timing.Lane and releases every
// lease after run returns.
func (s *Slots) RunAdmitted(ctx context.Context, guests uint32, timing LaneTiming, report func(reason string), run func(context.Context) error) (err error) {
	if timing.Admission <= 0 {
		return errors.New("lab hosts: lane admission requires a positive deadline")
	}
	admission, cancelAdmission := context.WithTimeout(ctx, timing.Admission)
	leases, err := s.AcquireNReporting(admission, guests, report)
	cancelAdmission()
	if err != nil {
		return fmt.Errorf("lab hosts: lane admission: %w", err)
	}
	defer func() {
		for _, lease := range leases {
			err = errors.Join(err, lease.Close())
		}
	}()
	if timing.Lane > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timing.Lane)
		defer cancel()
	}
	return run(ctx)
}

// Lease holds a kernel flock. Closing the last inherited descriptor or crashing
// releases it automatically, without stale PID cleanup or unlinking lock files.
type Lease struct {
	mu   sync.Mutex
	file *os.File
}

// Inherit appends the lease descriptor to cmd.ExtraFiles before cmd.Start. The
// child must retain that descriptor, and forward it to any longer-lived guests.
// Do not Close the lease until Start completes; call Wait for every started child.
// For children that close inherited descriptors, the alternative contract is to
// keep the parent's lease through teardown/Wait and enforce parent-death killing.
func (l *Lease) Inherit(cmd *exec.Cmd) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return errors.New("lab hosts: lease is closed")
	}
	if cmd == nil || cmd.Process != nil {
		return errors.New("lab hosts: inheritance requires an unstarted command")
	}
	cmd.ExtraFiles = append(cmd.ExtraFiles, l.file)
	return nil
}

// Close drops this process's descriptor, not the shared flock itself: inherited
// children continue reserving capacity until their own descriptors close.
func (l *Lease) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	if err != nil {
		return fmt.Errorf("lab hosts: close lease: %w", err)
	}
	return nil
}
