// SPDX-License-Identifier: Apache-2.0

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
	// Hangs are bounded by the test binary's -timeout; a short wall-clock
	// deadline here only measured how loaded the host was.
	ctx := t.Context()
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
	ctx := t.Context()
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
	lease, err := slots.Acquire(t.Context())
	if err != nil {
		t.Fatalf("stale ticket blocked admission: %v", err)
	}
	_ = lease.Close()
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale ticket not swept: %v", err)
	}
}

// waitFor polls condition until it holds. It has no wall-clock deadline of
// its own, which a loaded host would turn into a false failure; a condition
// that never holds is reported by the test binary's -timeout.
func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	for !condition() {
		if t.Context().Err() != nil {
			t.Fatal("test ended before the condition held")
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
	if err := <-admitted; err != nil {
		t.Fatal(err)
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
	if err := <-admitted; err != nil {
		t.Fatal(err)
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
		deadline, observed time.Time
		err                error
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
			ran <- admission{deadline: deadline, observed: time.Now(), err: ctx.Err()}
			return nil
		})
	}()
	<-queued
	time.Sleep(3 * lane) // queue for longer than the lane's own budget
	// The lane's deadline is set at admission, which follows the release:
	// it is no earlier than release+lane (a deadline counted from queueing
	// would be at least 3*lane earlier) and no later than its observation
	// plus lane. Neither bound depends on how quickly a loaded host runs.
	released := time.Now()
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	got := <-ran
	if got.err != nil || got.deadline.Before(released.Add(lane)) || got.deadline.After(got.observed.Add(lane)) {
		t.Fatalf("admitted lane deadline %v after release (observed %v), error %v; want the full %v counted from admission", got.deadline.Sub(released), got.observed.Sub(released), got.err, lane)
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

func TestAwaitMemoryTakesNoSlotAndReportsChanges(t *testing.T) {
	host := fixtureHost("await", t.TempDir())
	host.MaxGuests = 1
	slots, err := OpenSlots(host)
	if err != nil {
		t.Fatal(err)
	}
	held, err := func() (*Lease, error) {
		slots.memoryProbe = func(context.Context) (memoryAdmission, error) { return memoryAdmission{AvailableBytes: 64 << 30}, nil }
		return slots.Acquire(context.Background())
	}()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = held.Close() }()
	observations := make(chan memoryAdmission, 3)
	observations <- memoryAdmission{AvailableBytes: 1 << 30}
	observations <- memoryAdmission{AvailableBytes: 1 << 30}
	observations <- memoryAdmission{AvailableBytes: 64 << 30}
	slots.memoryProbe = func(context.Context) (memoryAdmission, error) { return <-observations, nil }
	var reasons []string
	ctx := t.Context()
	// Every slot is held, yet memory alone admits the host job.
	if err := slots.AwaitMemory(ctx, 1, func(reason string) { reasons = append(reasons, reason) }); err != nil {
		t.Fatal(err)
	}
	if len(reasons) != 1 || !strings.Contains(reasons[0], "MiB available") {
		t.Fatalf("reasons %q", reasons)
	}
	if active, err := slots.Count(); err != nil || active != 1 {
		t.Fatalf("host job took a slot: %d %v", active, err)
	}
}

// A waiter that started before the host's limit was raised (it read lab.json
// once) must admit by the new limit, not keep its stale one while later
// waiters overtake it under the new limit.
func TestWaiterAdoptsLaterConfiguredLimit(t *testing.T) {
	host := fixtureHost("raised", t.TempDir())
	host.MaxGuests = 3
	stale, err := openFixtureSlots(host)
	if err != nil {
		t.Fatal(err)
	}
	held, err := stale.AcquireN(t.Context(), 2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, lease := range held {
			_ = lease.Close()
		}
	}()
	admitted := make(chan []*Lease, 1)
	go func() {
		leases, err := stale.AcquireN(t.Context(), 2) // 2 of 3 held: waits
		if err != nil {
			t.Error(err)
		}
		admitted <- leases
	}()
	waitFor(t, func() bool { waiters, _, err := stale.olderWaiters(""); return err == nil && waiters == 1 })
	host.MaxGuests = 4
	if _, err := openFixtureSlots(host); err != nil { // a later lane, configured with 4
		t.Fatal(err)
	}
	// Admission by the stale limit of 3 never comes: the test binary's
	// -timeout reports the hang.
	leases := <-admitted
	if len(leases) != 2 {
		t.Fatalf("admitted %d guests", len(leases))
	}
	for _, lease := range leases {
		_ = lease.Close()
	}
}

// Strict first come, first served on a mixed queue: a two-guest head that the
// host cannot admit yet (here for memory, which a single guest would fit) is
// overtaken by none of the single-guest lanes queued after it, and is admitted
// before them once it fits.
func TestMixedQueueNeverStarvesItsMultiGuestHead(t *testing.T) {
	host := fixtureHost("mixed", t.TempDir())
	host.MaxGuests = 4
	host.MaxMemoryMib = 4 << 10
	var roomy atomic.Bool
	open := func() *Slots {
		t.Helper()
		slots, err := OpenSlots(host)
		if err != nil {
			t.Fatal(err)
		}
		slots.memoryProbe = func(context.Context) (memoryAdmission, error) {
			if roomy.Load() {
				return memoryAdmission{AvailableBytes: 64 << 30}, nil
			}
			return memoryAdmission{AvailableBytes: 13 << 30}, nil // one 4 GiB guest + headroom
		}
		return slots
	}
	type admission struct {
		name   string
		leases []*Lease
	}
	order := make(chan admission, 8)
	queued := 0
	acquire := func(name string, guests uint32) {
		queued++
		want := uint32(queued)
		slots := open()
		go func() {
			leases, err := slots.AcquireN(t.Context(), guests)
			if err != nil {
				t.Error(err)
			}
			order <- admission{name, leases}
		}()
		waitFor(t, func() bool {
			waiters, _, err := slots.olderWaiters("")
			return err == nil && waiters == want
		})
	}
	observer := open()
	// Each waiter's ticket is queued before the next starts, so tickets sort
	// in this order.
	acquire("pair", 2)
	for i := range 3 {
		acquire(fmt.Sprintf("single-%d", i), 1)
	}
	// Each single fits by slots and memory, but the head does not fit yet.
	time.Sleep(500 * time.Millisecond)
	select {
	case got := <-order:
		t.Fatalf("%s admitted ahead of the waiting two-guest head", got.name)
	default:
	}
	if active, err := observer.Count(); err != nil || active != 0 {
		t.Fatalf("waiters hold slots: %d %v", active, err)
	}
	roomy.Store(true)
	first := <-order
	if first.name != "pair" || len(first.leases) != 2 {
		t.Fatalf("first admitted %s (%d guests), want the two-guest head", first.name, len(first.leases))
	}
	for range 2 { // two singles fill the host; the third waits for a release
		got := <-order
		if !strings.HasPrefix(got.name, "single-") || len(got.leases) != 1 {
			t.Fatalf("admitted %s with %d guests", got.name, len(got.leases))
		}
		defer func() { _ = got.leases[0].Close() }()
	}
	for _, lease := range first.leases {
		if err := lease.Close(); err != nil {
			t.Fatal(err)
		}
	}
	last := <-order
	if len(last.leases) != 1 {
		t.Fatalf("last single admitted %d guests", len(last.leases))
	}
	_ = last.leases[0].Close()
}

// Waiters of one process that queue in the same clock tick each get their own
// ticket. Before tickets carried a sequence, two such waiters derived one
// name and the second failed with "waiter ticket is held"; that made
// TestSlotsConcurrentCapacity hang on loaded hosts.
func TestConcurrentWaitersGetDistinctTickets(t *testing.T) {
	slots, err := openFixtureSlots(fixtureHost("tickets", t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	const waiters = 64
	start := make(chan struct{})
	type ticket struct {
		name  string
		leave func() error
		err   error
	}
	tickets := make(chan ticket, waiters)
	for range waiters {
		go func() {
			<-start
			name, leave, err := slots.queue(1)
			tickets <- ticket{name, leave, err}
		}()
	}
	close(start)
	names := map[string]bool{}
	for range waiters {
		got := <-tickets
		if got.err != nil {
			t.Fatal(got.err)
		}
		if names[got.name] {
			t.Fatalf("ticket %s issued twice", got.name)
		}
		names[got.name] = true
		defer func() { _ = got.leave() }()
	}
	if older, demand, err := slots.olderWaiters(""); err != nil || older != waiters || demand != waiters {
		t.Fatalf("queue holds %d waiters for %d guests: %v", older, demand, err)
	}
}
