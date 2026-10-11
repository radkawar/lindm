package labhost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	labv1 "lindm/gen/lindm/lab/v1"
)

func openFixtureSlots(host *labv1.LabHost) (*Slots, error) {
	slots, err := OpenSlots(host)
	if err == nil {
		slots.memoryProbe = func(context.Context) (memoryAdmission, error) { return memoryAdmission{AvailableBytes: 128 << 30}, nil }
	}
	return slots, err
}

func TestAdmissionMemoryAndSwap(t *testing.T) {
	guest := uint64(4 << 30)
	for _, tc := range []struct {
		name                     string
		available, before, after uint64
		allow                    bool
	}{
		{"headroom", 12 << 30, 7, 7, true},
		{"insufficient", (12 << 30) - 1, 7, 7, false},
		{"swapping", 64 << 30, 7, 8, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := fixtureHost("memory", t.TempDir())
			host.MaxMemoryMib = uint32(guest >> 20)
			slots, err := openFixtureSlots(host)
			if err != nil {
				t.Fatal(err)
			}
			slots.memoryProbe = func(context.Context) (memoryAdmission, error) {
				return memoryAdmission{AvailableBytes: tc.available, SwapOutPagesBefore: tc.before, SwapOutPagesAfter: tc.after}, nil
			}
			leases, wait, err := slots.tryAcquireN(context.Background(), 1, "")
			if err != nil {
				t.Fatal(err)
			}
			if (wait == "") != tc.allow {
				t.Fatalf("wait reason %q with allow=%t", wait, tc.allow)
			}
			if (leases != nil) != tc.allow {
				t.Fatalf("admitted=%v expected=%v", leases != nil, tc.allow)
			}
			if leases != nil {
				lease := leases[0]
				t.Cleanup(func() {
					if err := lease.Close(); err != nil {
						t.Error(err)
					}
				})
				data, err := os.ReadFile(filepath.Join(slots.directory, "slot-0000.lock"))
				if err != nil {
					t.Fatal(err)
				}
				var record memoryAdmission
				if err := json.Unmarshal(data, &record); err != nil {
					t.Fatal(err)
				}
				if record.AvailableBytes != tc.available || record.HeadroomBytes != 8<<30 || record.GuestMemoryBytes != guest || record.SwapOutPagesAfter != tc.after {
					t.Fatalf("incorrect admission record: %+v", record)
				}
			}
		})
	}
	for _, data := range []string{"MemFree: 100 kB\n", "MemAvailable: bogus kB\n", "MemAvailable: 100 MB\n"} {
		if _, err := procCounter([]byte(data), "MemAvailable:", "kB"); err == nil {
			t.Fatalf("accepted invalid memory %q", data)
		}
	}
	if n, err := procCounter([]byte("pswpout 17\n"), "pswpout", ""); err != nil || n != 17 {
		t.Fatalf("counter=%d %v", n, err)
	}
}

func TestAdmissionCountsRetiredSlots(t *testing.T) {
	host := fixtureHost("reduce", t.TempDir())
	host.MaxGuests = 3
	slots, err := openFixtureSlots(host)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	leases := make([]*Lease, 0, 3)
	defer func() {
		for _, lease := range leases {
			_ = lease.Close()
		}
	}()
	for range 3 {
		lease, err := slots.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		leases = append(leases, lease)
	}
	host.MaxGuests = 1
	reduced, err := openFixtureSlots(host)
	if err != nil {
		t.Fatal(err)
	}
	if err := leases[0].Close(); err != nil {
		t.Fatal(err)
	}
	if active, err := reduced.Count(); err != nil || active != 2 {
		t.Fatalf("retired active=%d %v", active, err)
	}
	if leases, _, err := reduced.tryAcquireN(ctx, 1, ""); err != nil || leases != nil {
		for _, lease := range leases {
			_ = lease.Close()
		}
		t.Fatalf("ignored retired slots: %v", err)
	}
	if err := leases[1].Close(); err != nil {
		t.Fatal(err)
	}
	if err := leases[2].Close(); err != nil {
		t.Fatal(err)
	}
	lease, err := reduced.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = lease.Close()
}

// Two firewall-style lanes, each needing two concurrent guests, share a
// three-slot host while a single-guest lane holds one slot. Admitting one lease
// at a time lets each pair lane take one of the two free slots and wait forever
// for its second: a hold-and-wait deadlock. Atomic admission must run both
// lanes to completion, one after the other, never holding a partial set.
func TestConcurrentMultiGuestLanesDoNotDeadlock(t *testing.T) {
	host := fixtureHost("pairs", t.TempDir())
	host.MaxGuests = 3
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	single, err := openFixtureSlots(host)
	if err != nil {
		t.Fatal(err)
	}
	other, err := single.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Close() }()
	var held atomic.Int32
	errs := make(chan error, 2)
	for range 2 {
		go func() {
			// Each lane is its own process in practice; separate Slots values
			// open separate flock descriptions exactly like separate processes.
			slots, err := openFixtureSlots(host)
			if err != nil {
				errs <- err
				return
			}
			leases, err := slots.AcquireN(ctx, 2)
			if err != nil {
				errs <- err
				return
			}
			if held.Add(2) > 2 {
				errs <- errors.New("admitted more guests than the host capacity")
				return
			}
			if active, err := slots.Count(); err != nil || active != 3 {
				errs <- fmt.Errorf("a waiting lane holds part of its capacity: active=%d %v", active, err)
				return
			}
			time.Sleep(100 * time.Millisecond) // The lane's guests run.
			held.Add(-2)
			for _, lease := range leases {
				err = errors.Join(err, lease.Close())
			}
			errs <- err
		}()
	}
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}

// With one free slot, a waiting two-guest lane must hold nothing (no partial
// reservation), and single-guest lanes arriving after it must not overtake
// it: otherwise a steady stream of single lanes starves the pair forever.
func TestWaitingMultiGuestLaneHoldsNothingAndIsNotStarved(t *testing.T) {
	host := fixtureHost("partial", t.TempDir())
	host.MaxGuests = 3
	slots, err := openFixtureSlots(host)
	if err != nil {
		t.Fatal(err)
	}
	held, err := slots.AcquireN(context.Background(), 2)
	if err != nil {
		t.Fatal(err)
	}
	pair := make(chan []*Lease, 1)
	pairErr := make(chan error, 1)
	go func() {
		leases, err := slots.AcquireN(context.Background(), 2)
		pair <- leases
		pairErr <- err
	}()
	waitFor(t, func() bool { waiters, _, err := slots.olderWaiters(""); return err == nil && waiters == 1 })
	if active, err := slots.Count(); err != nil || active != 2 {
		t.Fatalf("waiting pair lane retained a slot: active=%d %v", active, err)
	}
	// A younger single-guest lane must queue behind the pair, not take the slot.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if single, err := slots.Acquire(ctx); !errors.Is(err, context.DeadlineExceeded) {
		if single != nil {
			_ = single.Close()
		}
		t.Fatalf("younger single-guest lane overtook the waiting pair: %v", err)
	}
	// Freeing one slot admits the pair (two free slots), ahead of later lanes.
	if err := held[0].Close(); err != nil {
		t.Fatal(err)
	}
	leases := <-pair
	if err := <-pairErr; err != nil || len(leases) != 2 {
		t.Fatalf("pair lane not admitted when capacity freed: %d %v", len(leases), err)
	}
	for _, lease := range append(leases, held[1]) {
		if err := lease.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if waiters, _, err := slots.olderWaiters(""); err != nil || waiters != 0 {
		t.Fatalf("admitted waiter left a live ticket: %d %v", waiters, err)
	}
}

// A waiter that died without removing its ticket must not block admission.
func TestStaleWaiterTicketIsSwept(t *testing.T) {
	host := fixtureHost("stale", t.TempDir())
	host.MaxGuests = 1
	slots, err := openFixtureSlots(host)
	if err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(slots.directory, fmt.Sprintf("%s%020d-%010d-1.lock", waiterPrefix, 1, 1))
	if err := os.WriteFile(stale, nil, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	lease, err := slots.Acquire(ctx)
	if err != nil {
		t.Fatalf("stale ticket blocked admission: %v", err)
	}
	_ = lease.Close()
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale ticket not swept: %v", err)
	}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestMultiGuestAdmissionGuardsSummedMemoryAndCapacity(t *testing.T) {
	host := fixtureHost("sum", t.TempDir())
	host.MaxGuests = 3
	host.MaxMemoryMib = 4 << 10
	slots, err := openFixtureSlots(host)
	if err != nil {
		t.Fatal(err)
	}
	// Room for one 4 GiB guest plus the 8 GiB headroom, not for two.
	slots.memoryProbe = func(context.Context) (memoryAdmission, error) {
		return memoryAdmission{AvailableBytes: 13 << 30}, nil
	}
	leases, wait, err := slots.tryAcquireN(context.Background(), 2, "")
	if err != nil || leases != nil {
		t.Fatalf("two guests admitted against one guest's memory: %d %v", len(leases), err)
	}
	if !strings.Contains(wait, "MiB available") {
		t.Fatalf("memory refusal reason %q", wait)
	}
	if active, err := slots.Count(); err != nil || active != 0 {
		t.Fatalf("refused admission retained slots: %d %v", active, err)
	}
	one, _, err := slots.tryAcquireN(context.Background(), 1, "")
	if err != nil || len(one) != 1 {
		t.Fatalf("single guest refused: %v", err)
	}
	defer func() { _ = one[0].Close() }()
	if _, _, err := slots.tryAcquireN(context.Background(), 4, ""); err == nil {
		t.Fatal("lane larger than the host was not refused")
	}
}

func TestAcquireReportingNamesEachChangedWaitReasonOnce(t *testing.T) {
	host := fixtureHost("report", t.TempDir())
	host.MaxGuests = 1
	slots, err := OpenSlots(host)
	if err != nil {
		t.Fatal(err)
	}
	slots.memoryProbe = func(context.Context) (memoryAdmission, error) {
		return memoryAdmission{AvailableBytes: 64 << 30}, nil
	}
	held, err := slots.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	reasons := make(chan string, 16)
	admitted := make(chan error, 1)
	go func() {
		leases, err := slots.AcquireNReporting(context.Background(), 1, func(reason string) { reasons <- reason })
		for _, lease := range leases {
			err = errors.Join(err, lease.Close())
		}
		admitted <- err
	}()
	if reason := <-reasons; reason != "1 of 1 slots held; 1 needed" {
		t.Fatalf("wait reason %q", reason)
	}
	time.Sleep(300 * time.Millisecond) // several polls with an unchanged reason
	if len(reasons) != 0 {
		t.Fatalf("repeated an unchanged reason: %q", <-reasons)
	}
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-admitted:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("not admitted after the slot was released")
	}
}

// Contention on the admission guard is transient poll noise: many queued
// waiters would otherwise alternate it with the real queue reason forever.
func TestAcquireReportingOmitsTransientAdmissionContention(t *testing.T) {
	host := fixtureHost("busy", t.TempDir())
	host.MaxGuests = 1
	slots, err := openFixtureSlots(host)
	if err != nil {
		t.Fatal(err)
	}
	held, err := slots.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	guard, err := slots.openName(".admission.lock")
	if err != nil {
		t.Fatal(err)
	}
	if locked, err := lockSlot(guard); err != nil || !locked {
		t.Fatalf("hold admission guard: %v %v", locked, err)
	}
	reasons := make(chan string, 16)
	admitted := make(chan error, 1)
	go func() {
		leases, err := slots.AcquireNReporting(context.Background(), 1, func(reason string) { reasons <- reason })
		for _, lease := range leases {
			err = errors.Join(err, lease.Close())
		}
		admitted <- err
	}()
	time.Sleep(300 * time.Millisecond) // several polls refused by the guard
	if len(reasons) != 0 {
		t.Fatalf("reported transient contention: %q", <-reasons)
	}
	if err := guard.Close(); err != nil {
		t.Fatal(err)
	}
	if reason := <-reasons; reason != "1 of 1 slots held; 1 needed" {
		t.Fatalf("wait reason %q", reason)
	}
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-admitted:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("not admitted after the slot was released")
	}
}

// A lane that queued longer than its own timeout must still receive the whole
// lane timeout once admitted; queue time is bounded only by Admission.
func TestRunAdmittedStartsLaneDeadlineAfterAdmission(t *testing.T) {
	host := fixtureHost("deadline", t.TempDir())
	host.MaxGuests = 1
	slots, err := openFixtureSlots(host)
	if err != nil {
		t.Fatal(err)
	}
	held, err := slots.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	const lane = 200 * time.Millisecond
	queued := make(chan struct{})
	type admission struct {
		remaining time.Duration
		err       error
	}
	ran := make(chan admission, 1)
	result := make(chan error, 1)
	go func() {
		result <- slots.RunAdmitted(context.Background(), 1, LaneTiming{Admission: time.Minute, Lane: lane}, func(string) { close(queued) }, func(ctx context.Context) error {
			deadline, ok := ctx.Deadline()
			if !ok {
				ran <- admission{err: errors.New("lane has no deadline")}
				return nil
			}
			ran <- admission{remaining: time.Until(deadline), err: ctx.Err()}
			return nil
		})
	}()
	<-queued
	time.Sleep(3 * lane) // queue for longer than the lane's own budget
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-ran:
		if got.err != nil || got.remaining < lane/2 || got.remaining > lane {
			t.Fatalf("admitted lane remaining %v, error %v; want its full %v", got.remaining, got.err, lane)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("not admitted after the slot was released")
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if count, err := slots.Count(); err != nil || count != 0 {
		t.Fatalf("lane leases not released: %d held, %v", count, err)
	}
	held, err = slots.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()
	if err := slots.RunAdmitted(context.Background(), 1, LaneTiming{Admission: lane, Lane: time.Minute}, nil, func(context.Context) error {
		t.Error("lane ran without admission")
		return nil
	}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("admission wait beyond its bound returned %v", err)
	}
}
