package feed

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRefreshProgressAbortsOnlyWithoutProgress(t *testing.T) {
	idle := 80 * time.Millisecond
	ctx, progress := newRefreshProgress(t.Context(), idle, time.Hour)
	defer progress.Close()
	// Steady marks keep a refresh alive well past several idle windows.
	for deadline := time.Now().Add(4 * idle); time.Now().Before(deadline); time.Sleep(idle / 4) {
		if err := progress.Mark(); err != nil {
			t.Fatalf("progressing refresh aborted: %v", err)
		}
	}
	select {
	case <-ctx.Done():
	case <-time.After(10 * idle):
		t.Fatal("silent refresh was not aborted")
	}
	if cause := context.Cause(ctx); !errors.Is(cause, ErrRefreshStalled) {
		t.Fatalf("stall cause = %v", cause)
	}
	if err := progress.Mark(); !errors.Is(err, ErrRefreshStalled) {
		t.Fatalf("mark after stall = %v", err)
	}
}

func TestRefreshProgressCeilingDespiteProgress(t *testing.T) {
	ceiling := 150 * time.Millisecond
	ctx, progress := newRefreshProgress(t.Context(), time.Hour, ceiling)
	defer progress.Close()
	for ctx.Err() == nil {
		if err := progress.Mark(); err != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if cause := context.Cause(ctx); !errors.Is(cause, ErrRefreshCeiling) {
		t.Fatalf("ceiling cause = %v", cause)
	}
}

func TestRefreshProgressCloseJoinsWatchdog(t *testing.T) {
	ctx, progress := newRefreshProgress(t.Context(), time.Hour, time.Hour)
	progress.Close()
	if ctx.Err() == nil {
		t.Fatal("closed refresh context still live")
	}
}
