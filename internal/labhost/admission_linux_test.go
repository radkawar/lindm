package labhost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
			leases, err := slots.tryAcquireN(context.Background(), 1)
			if err != nil {
				t.Fatal(err)
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
	if leases, err := reduced.tryAcquireN(ctx, 1); err != nil || leases != nil {
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

// The deterministic core of the deadlock: with a single free slot, a two-guest
// lane must keep waiting without taking it, so other lanes can still use it.
func TestMultiGuestLaneNeverHoldsPartialCapacity(t *testing.T) {
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
	defer func() {
		for _, lease := range held {
			_ = lease.Close()
		}
	}()
	// A pair lane waits for capacity concurrently with a single-guest lane.
	waiting, stop := context.WithCancel(context.Background())
	pair := make(chan error, 1)
	go func() {
		leases, err := slots.AcquireN(waiting, 2)
		for _, lease := range leases {
			err = errors.Join(err, lease.Close(), errors.New("pair admitted into one free slot"))
		}
		pair <- err
	}()
	// While the pair is waiting, the one free slot remains admissible; a
	// lease-at-a-time pair would have taken it and starved this lane.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	single, err := slots.Acquire(ctx)
	if err != nil {
		t.Fatalf("free slot unavailable while a pair lane waits: %v", err)
	}
	stop()
	if err := <-pair; !errors.Is(err, context.Canceled) {
		t.Fatalf("waiting pair lane: %v", err)
	}
	if active, err := slots.Count(); err != nil || active != 3 {
		t.Fatalf("active=%d %v", active, err)
	}
	_ = single.Close()
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
	if leases, err := slots.tryAcquireN(context.Background(), 2); err != nil || leases != nil {
		t.Fatalf("two guests admitted against one guest's memory: %d %v", len(leases), err)
	}
	if active, err := slots.Count(); err != nil || active != 0 {
		t.Fatalf("refused admission retained slots: %d %v", active, err)
	}
	one, err := slots.tryAcquireN(context.Background(), 1)
	if err != nil || len(one) != 1 {
		t.Fatalf("single guest refused: %v", err)
	}
	defer func() { _ = one[0].Close() }()
	if _, err := slots.tryAcquireN(context.Background(), 4); err == nil {
		t.Fatal("lane larger than the host was not refused")
	}
}
