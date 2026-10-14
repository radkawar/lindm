// SPDX-License-Identifier: Apache-2.0

package labhost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const memoryHeadroomBytes uint64 = 8 << 30

type memoryAdmission struct {
	ObservedAt         time.Time `json:"observed_at"`
	AvailableBytes     uint64    `json:"mem_available_bytes"`
	GuestMemoryBytes   uint64    `json:"guest_memory_ceiling_bytes"`
	HeadroomBytes      uint64    `json:"headroom_bytes"`
	SwapOutPagesBefore uint64    `json:"swap_out_pages_before"`
	SwapOutPagesAfter  uint64    `json:"swap_out_pages_after"`
	SampleMilliseconds int64     `json:"sample_milliseconds"`
	PID                int       `json:"pid"`
}

func procCounter(data []byte, field string, unit string) (uint64, error) {
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != field {
			continue
		}
		expected := 2
		if unit != "" {
			expected = 3
		}
		if len(fields) != expected || unit != "" && fields[2] != unit {
			return 0, fmt.Errorf("invalid native %s counter", field)
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid native %s counter: %w", field, err)
		}
		return value, nil
	}
	return 0, fmt.Errorf("missing native %s counter", field)
}

func readSwapOut() (uint64, error) {
	data, err := os.ReadFile("/proc/vmstat")
	if err != nil {
		return 0, err
	}
	return procCounter(data, "pswpout", "")
}

func observeMemory(ctx context.Context) (memoryAdmission, error) {
	var result memoryAdmission
	before, err := readSwapOut()
	if err != nil {
		return result, err
	}
	started := time.Now()
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return result, ctx.Err()
	case <-timer.C:
	}
	after, err := readSwapOut()
	if err != nil {
		return result, err
	}
	if after < before {
		return result, errors.New("native swap-out counter decreased during admission")
	}
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return result, err
	}
	available, err := procCounter(data, "MemAvailable:", "kB")
	if err != nil {
		return result, err
	}
	if available > ^uint64(0)/1024 {
		return result, errors.New("native available memory counter overflow")
	}
	result = memoryAdmission{ObservedAt: time.Now().UTC(), AvailableBytes: available * 1024, SwapOutPagesBefore: before, SwapOutPagesAfter: after, SampleMilliseconds: time.Since(started).Milliseconds(), PID: os.Getpid()}
	return result, nil
}

func (m memoryAdmission) allows(guestBytes uint64) bool {
	return m.SwapOutPagesAfter == m.SwapOutPagesBefore && m.AvailableBytes >= guestBytes+memoryHeadroomBytes
}

// refusal names why the observation does not admit guestBytes for guests, or
// returns "" when it does.
func (m memoryAdmission) refusal(guestBytes uint64, guests uint32) string {
	switch {
	case m.allows(guestBytes):
		return ""
	case m.SwapOutPagesAfter != m.SwapOutPagesBefore:
		return "host swapped out pages during the admission sample"
	default:
		return fmt.Sprintf("%d MiB available < %d MiB needed (%d guests + headroom)", m.AvailableBytes>>20, (guestBytes+memoryHeadroomBytes)>>20, guests)
	}
}

// AwaitMemory waits until the host's memory admission would admit guests
// guest-equivalents, without taking a slot or a FIFO ticket, calling report
// with each changed wait reason. It is for host jobs that are not guests and
// must not queue behind lanes, yet must not drive the host into swap.
func (s *Slots) AwaitMemory(ctx context.Context, guests uint32, report func(reason string)) error {
	guestBytes := uint64(guests) * (uint64(s.memoryMib) << 20)
	var last string
	for {
		observation, err := s.memoryProbe(ctx)
		if err != nil {
			return fmt.Errorf("lab hosts: memory admission: %w", err)
		}
		wait := observation.refusal(guestBytes, guests)
		if wait == "" {
			return nil
		}
		if report != nil && wait != last {
			report(wait)
			last = wait
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// admissionBusy is the transient wait while another waiter's poll holds the
// admission guard; it says nothing about the queue, so it is never reported.
const admissionBusy = "another admission is in progress"

// Serialize admission so lowering a configured limit also counts older slots
// outside the new range. Never unlink those identities while holders may exist.
// A lane's guests are admitted together or not at all: holding one slot while
// waiting for another is a hold-and-wait deadlock once two multi-guest lanes
// share a host. Admission is strictly first come, first served: only the
// oldest live waiter is admitted, so no younger lane (of any size) can take the
// slots or memory the head is waiting for and a multi-guest head never
// starves. The limit is re-read on every check. Memory admission covers the
// sum of the requested guests. A nil result with a nil error carries the reason
// admission must wait. An empty ticket queues behind every live waiter.
func (s *Slots) tryAcquireN(ctx context.Context, guests uint32, ticket string) (_ []*Lease, wait string, resultErr error) {
	guard, err := s.openName(".admission.lock")
	if err != nil {
		return nil, "", err
	}
	defer func() { resultErr = errors.Join(resultErr, guard.Close()) }()
	locked, err := lockSlot(guard)
	if err != nil || !locked {
		return nil, admissionBusy, err
	}
	capacity, err := s.currentCapacity()
	if err != nil {
		return nil, "", err
	}
	if guests == 0 || guests > capacity {
		return nil, "", fmt.Errorf("lab hosts: lane needs %d guests but the host admits %d", guests, capacity)
	}
	active, err := s.Count()
	if err != nil {
		return nil, "", err
	}
	older, demand, err := s.olderWaiters(ticket)
	if err != nil {
		return nil, "", err
	}
	if older != 0 {
		return nil, fmt.Sprintf("behind %d older waiters (%d guests); %d of %d slots held", older, demand, active, capacity), nil
	}
	if active > capacity-guests {
		return nil, fmt.Sprintf("%d of %d slots held; %d needed", active, capacity, guests), nil
	}
	observation, err := s.memoryProbe(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("lab hosts: memory admission: %w", err)
	}
	guestBytes := uint64(guests) * (uint64(s.memoryMib) << 20)
	if wait := observation.refusal(guestBytes, guests); wait != "" {
		return nil, wait, nil
	}
	observation.GuestMemoryBytes, observation.HeadroomBytes = guestBytes, memoryHeadroomBytes
	data, err := json.Marshal(observation)
	if err != nil {
		return nil, "", err
	}
	leases := make([]*Lease, 0, guests)
	release := func(err error) ([]*Lease, string, error) {
		for _, lease := range leases {
			err = errors.Join(err, lease.Close())
		}
		return nil, "retired slots beyond the configured limit are held", err
	}
	for index := range capacity {
		if uint32(len(leases)) == guests {
			break
		}
		file, err := s.open(index)
		if err != nil {
			return release(err)
		}
		locked, lockErr := lockSlot(file)
		if lockErr != nil || !locked {
			if err := errors.Join(lockErr, file.Close()); err != nil {
				return release(err)
			}
			continue
		}
		_, err = file.WriteAt(append(data, '\n'), 0)
		if err == nil {
			err = file.Truncate(int64(len(data) + 1))
		}
		if err == nil {
			err = file.Sync()
		}
		if err != nil {
			return release(errors.Join(err, file.Close()))
		}
		leases = append(leases, &Lease{file: file})
	}
	if uint32(len(leases)) != guests {
		// Retired slots beyond a reduced limit can hold capacity; never admit part.
		return release(nil)
	}
	return leases, "", nil
}

const waiterPrefix = "waiter-"

// queue publishes a first-come ticket held by an exclusive flock while the
// caller waits. Names sort by arrival; the demanded guests are in the name.
// The ticket is locked under a private name before it is renamed into the
// queue, so a reader never mistakes a just-created ticket for a stale one.
// A ticket whose holder died loses its flock and is swept by later readers.
func (s *Slots) queue(guests uint32) (string, func() error, error) {
	name := fmt.Sprintf("%s%020d-%010d-%d.lock", waiterPrefix, time.Now().UnixNano(), os.Getpid(), guests)
	pending := filepath.Join(s.directory, "pending-"+name)
	file, err := s.openName("pending-" + name)
	if err != nil {
		return "", nil, err
	}
	if locked, err := lockSlot(file); err != nil || !locked {
		return "", nil, errors.Join(errors.New("lab hosts: waiter ticket is held"), err, file.Close(), os.Remove(pending))
	}
	if err := os.Rename(pending, filepath.Join(s.directory, name)); err != nil {
		return "", nil, errors.Join(err, file.Close(), os.Remove(pending))
	}
	return name, func() error {
		removeErr := os.Remove(filepath.Join(s.directory, name))
		if errors.Is(removeErr, os.ErrNotExist) {
			removeErr = nil
		}
		return errors.Join(removeErr, file.Close())
	}, nil
}

// olderWaiters counts live tickets queued before ticket and the guests they
// demand. The caller holds the admission lock.
func (s *Slots) olderWaiters(ticket string) (waiters, guests uint32, err error) {
	entries, err := os.ReadDir(s.directory)
	if err != nil {
		return 0, 0, err
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, waiterPrefix) || name == ticket || (ticket != "" && name > ticket) {
			continue
		}
		fields := strings.Split(strings.TrimSuffix(strings.TrimPrefix(name, waiterPrefix), ".lock"), "-")
		demand, parseErr := strconv.ParseUint(fields[len(fields)-1], 10, 32)
		if len(fields) != 3 || parseErr != nil {
			return 0, 0, fmt.Errorf("invalid waiter ticket %q", name)
		}
		path := filepath.Join(s.directory, name)
		file, err := os.OpenFile(path, os.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return 0, 0, err
		}
		stale, lockErr := lockSlot(file)
		if stale {
			// The waiter exited without removing its ticket.
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				lockErr = errors.Join(lockErr, err)
			}
		}
		if err := errors.Join(lockErr, file.Close()); err != nil {
			return 0, 0, err
		}
		if !stale {
			waiters++
			guests += uint32(demand)
		}
	}
	return waiters, guests, nil
}

func (s *Slots) indices() ([]uint32, error) {
	entries, err := os.ReadDir(s.directory)
	if err != nil {
		return nil, err
	}
	indices := make([]uint32, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "slot-") || !strings.HasSuffix(name, ".lock") {
			continue
		}
		value, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(name, "slot-"), ".lock"), 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid lease identity %q", name)
		}
		indices = append(indices, uint32(value))
	}
	return indices, nil
}
