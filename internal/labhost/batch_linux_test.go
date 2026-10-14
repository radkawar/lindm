// SPDX-License-Identifier: Apache-2.0

package labhost

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConcurrentTwoGuestDemosReserveWholeFootprints(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	slots, err := openFixtureSlots(fixtureHost("demo-batch", t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	firstCtx, stopFirst := context.WithCancel(ctx)
	defer stopFirst()
	firstReady, firstDone := startBatchFixture(slots, firstCtx, 2, nil)
	credential := receiveBatchFixture(t, ctx, firstReady)
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	workers := make(chan error, 2)
	for range 2 {
		go func() {
			workers <- slots.RunBatchWorker(ctx, credential, func(ctx context.Context) error {
				entered <- struct{}{}
				select {
				case <-release:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			})
		}()
	}
	for range 2 {
		receiveBatchFixture(t, ctx, entered)
	}
	queued := make(chan struct{}, 1)
	secondCtx, stopSecond := context.WithCancel(ctx)
	defer stopSecond()
	secondReady, secondDone := startBatchFixture(slots, secondCtx, 2, func(string) {
		select {
		case queued <- struct{}{}:
		default:
		}
	})
	receiveBatchFixture(t, ctx, queued)
	select {
	case <-secondReady:
		t.Fatal("second demo entered while the first owns the host footprint")
	default:
	}
	if count, err := slots.Count(); err != nil || count != 2 {
		t.Fatalf("first demo held %d slots: %v", count, err)
	}
	close(release)
	for range 2 {
		if err := receiveBatchFixture(t, ctx, workers); err != nil {
			t.Fatal(err)
		}
	}
	stopFirst()
	if err := receiveBatchFixture(t, ctx, firstDone); !errors.Is(err, context.Canceled) {
		t.Fatalf("first broker exit: %v", err)
	}
	credential = receiveBatchFixture(t, ctx, secondReady)
	for range 2 {
		if err := slots.RunBatchWorker(ctx, credential, func(context.Context) error { return nil }); err != nil {
			t.Fatalf("second demo did not complete after the first: %v", err)
		}
	}
	stopSecond()
	if err := receiveBatchFixture(t, ctx, secondDone); !errors.Is(err, context.Canceled) {
		t.Fatalf("second broker exit: %v", err)
	}
	if count, err := slots.Count(); err != nil || count != 0 {
		t.Fatalf("completed demos retain %d slots: %v", count, err)
	}
}

func TestBatchDisconnectRetainsWorkerLeaseThroughTeardown(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	slots, err := openFixtureSlots(fixtureHost("disconnect", t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	brokerCtx, stopBroker := context.WithCancel(ctx)
	defer stopBroker()
	ready, brokerDone := startBatchFixture(slots, brokerCtx, 1, nil)
	credential := receiveBatchFixture(t, ctx, ready)
	started, canceled := make(chan struct{}), make(chan struct{})
	teardown := make(chan struct{})
	workerDone := make(chan error, 1)
	go func() {
		workerDone <- slots.RunBatchWorker(ctx, credential, func(worker context.Context) error {
			close(started)
			<-worker.Done()
			close(canceled)
			select {
			case <-teardown:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()
	receiveBatchFixture(t, ctx, started)
	stopBroker()
	receiveBatchFixture(t, ctx, canceled)
	if err := receiveBatchFixture(t, ctx, brokerDone); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if count, err := slots.Count(); err != nil || count != 1 {
		t.Fatalf("broker disconnect freed live worker capacity: count=%d err=%v", count, err)
	}
	close(teardown)
	if err := receiveBatchFixture(t, ctx, workerDone); err != nil {
		t.Fatal(err)
	}
	if count, err := slots.Count(); err != nil || count != 0 {
		t.Fatalf("worker teardown retains capacity: count=%d err=%v", count, err)
	}
}

// Ctrl-C while a demo waits in FIFO admission is an ordinary stop: the broker
// exits on stdin EOF without printing a credential.
func TestBatchAcquireCanceledWhileQueuedReportsCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	binary := filepath.Join(t.TempDir(), "lab")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\ncat >/dev/null\n"), 0700); err != nil {
		t.Fatal(err)
	}
	queued, stop := context.WithCancel(ctx)
	timer := time.AfterFunc(100*time.Millisecond, stop)
	defer timer.Stop()
	reservation, err := BatchRequest{Host: fixtureHost("queued", t.TempDir()), Guests: 1, LabBinary: binary}.Acquire(queued)
	if reservation != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("queued cancellation: reservation=%v err=%v", reservation, err)
	}
}

func TestBatchRequiresCredentialAndReservedDescriptor(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	slots, err := openFixtureSlots(fixtureHost("authentication", t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	brokerCtx, stopBroker := context.WithCancel(ctx)
	defer stopBroker()
	ready, done := startBatchFixture(slots, brokerCtx, 1, nil)
	credential := receiveBatchFixture(t, ctx, ready)
	decoded, err := base64.RawURLEncoding.DecodeString(credential)
	if err != nil {
		t.Fatal(err)
	}
	decoded[0] ^= 1
	bad := base64.RawURLEncoding.EncodeToString(decoded)
	called := false
	run := func(context.Context) error { called = true; return nil }
	if err := slots.RunBatchWorker(ctx, bad, run); err == nil || called {
		t.Fatal("untrusted credential bypassed admission")
	}
	other, err := openFixtureSlots(fixtureHost("other-host", t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	if err := other.RunBatchWorker(ctx, credential, run); err == nil || called {
		t.Fatal("descriptor from a different capacity namespace admitted")
	}
	if err := slots.RunBatchWorker(ctx, credential, run); err == nil || called {
		t.Fatal("already distributed reservation admitted another worker")
	}
	stopBroker()
	if err := receiveBatchFixture(t, ctx, done); !errors.Is(err, context.Canceled) {
		t.Fatalf("broker exit: %v", err)
	}
	unlocked, err := slots.open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := unlocked.Close(); err != nil {
			t.Error(err)
		}
	}()
	if err := slots.validateBatchLease(unlocked); err == nil {
		t.Fatal("unreserved slot descriptor bypassed batch admission")
	}
}

func TestBatchCredentialFileRequiresPrivateCustody(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(path, []byte("opaque"), 0600); err != nil {
		t.Fatal(err)
	}
	if value, err := ReadBatchCredential(path); err != nil || value != "opaque" {
		t.Fatalf("credential=%q err=%v", value, err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBatchCredential(path); err == nil {
		t.Fatal("read publicly accessible batch credential")
	}
}

func startBatchFixture(slots *Slots, ctx context.Context, guests uint32, report func(string)) (<-chan string, <-chan error) {
	ready := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- slots.ServeBatch(ctx, guests, 10*time.Second, report, func(credential string) error {
			ready <- credential
			return nil
		})
	}()
	return ready, done
}

func receiveBatchFixture[T any](t *testing.T, ctx context.Context, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-ctx.Done():
		t.Fatal(ctx.Err())
		var zero T
		return zero
	}
}
