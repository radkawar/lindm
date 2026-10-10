package labhost

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
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
			lease, err := slots.tryAcquire(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if (lease != nil) != tc.allow {
				t.Fatalf("admitted=%v expected=%v", lease != nil, tc.allow)
			}
			if lease != nil {
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
	if lease, err := reduced.tryAcquire(ctx); err != nil || lease != nil {
		if lease != nil {
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
