// SPDX-License-Identifier: Apache-2.0

//go:build linux

package recovery

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestEffectGateConsumesBeforeNetworkAndNeverReplays(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := journal.Close(); err != nil {
			t.Error(err)
		}
	}()
	now := time.Now()
	networkLoss := errors.New("lost server acknowledgment")
	calls := 0
	gate := &effectGate{journal: journal, started: time.Second, expires: now.Add(30 * time.Second), clock: func() (time.Time, time.Time, error) { return now, now, nil }, boottime: func() (time.Duration, error) { return time.Second, nil }, verify: func(context.Context) error { return nil }, checkpoint: func(context.Context) error {
		calls++
		consumed, err := journal.Consumed()
		if err != nil || !consumed {
			t.Fatalf("network before durable consumption: %v %v", consumed, err)
		}
		return networkLoss
	}}
	if err := gate.consume(context.Background()); !errors.Is(err, networkLoss) {
		t.Fatal(err)
	}
	if err := gate.consume(context.Background()); !errors.Is(err, ErrConsumed) {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("checkpoint replayed %d times", calls)
	}
}

func TestEffectGateRejectsGrantExpiringDuringCheckpoint(t *testing.T) {
	for _, suspend := range []bool{false, true} {
		t.Run(map[bool]string{false: "authenticated_time", true: "suspend"}[suspend], func(t *testing.T) {
			directory := t.TempDir()
			if err := os.Chmod(directory, 0700); err != nil {
				t.Fatal(err)
			}
			journal, err := OpenJournal(directory)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := journal.Close(); err != nil {
					t.Error(err)
				}
			}()
			now := time.Now()
			monotonic := time.Second
			gate := &effectGate{journal: journal, started: monotonic, expires: now.Add(30 * time.Second), clock: func() (time.Time, time.Time, error) { return now, now, nil }, boottime: func() (time.Duration, error) { return monotonic, nil }, verify: func(context.Context) error { return nil }, checkpoint: func(context.Context) error {
				if suspend {
					monotonic += 30 * time.Second
				} else {
					now = now.Add(30 * time.Second)
				}
				return nil
			}}
			if err := gate.consume(context.Background()); !errors.Is(err, ErrAuthorityExpired) {
				t.Fatalf("expired effect authorized: %v", err)
			}
			consumed, err := journal.Consumed()
			if err != nil || !consumed {
				t.Fatalf("ambiguous checkpoint lost reservation: %v %v", consumed, err)
			}
		})
	}
}

func TestEffectGateRejectsExpiredBeforeReservation(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := journal.Close(); err != nil {
			t.Error(err)
		}
	}()
	now := time.Now()
	gate := &effectGate{journal: journal, started: time.Second, expires: now, clock: func() (time.Time, time.Time, error) { return now, now, nil }, boottime: func() (time.Duration, error) { return time.Second, nil }, verify: func(context.Context) error { t.Fatal("verified expired grant"); return nil }, checkpoint: func(context.Context) error { t.Fatal("committed expired grant"); return nil }}
	if err := gate.consume(context.Background()); !errors.Is(err, ErrAuthorityExpired) {
		t.Fatal(err)
	}
	consumed, err := journal.Consumed()
	if err != nil || consumed {
		t.Fatalf("reserved without fresh authority: %v %v", consumed, err)
	}
}

func TestEffectGateExpiresDuringFinalSignatureVerification(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	journal, err := OpenJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := journal.Close(); err != nil {
			t.Error(err)
		}
	}()
	now := time.Now()
	monotonic := time.Second
	verifications, checkpoints := 0, 0
	gate := &effectGate{
		journal: journal, started: monotonic, expires: now.Add(30 * time.Second),
		clock:    func() (time.Time, time.Time, error) { return now, now, nil },
		boottime: func() (time.Duration, error) { return monotonic, nil },
		verify: func(context.Context) error {
			verifications++
			if verifications == 2 {
				// Model suspend while verifying after durable checkpoint.
				monotonic += 30 * time.Second
				now = now.Add(30 * time.Second)
			}
			return nil
		},
		checkpoint: func(context.Context) error { checkpoints++; return nil },
	}
	if err := gate.consume(t.Context()); !errors.Is(err, ErrAuthorityExpired) {
		t.Fatalf("expired effect released: %v", err)
	}
	consumed, err := journal.Consumed()
	if err != nil || !consumed || checkpoints != 1 || verifications != 2 {
		t.Fatalf("consumed=%v checkpoints=%d verifications=%d: %v", consumed, checkpoints, verifications, err)
	}
}
