package device

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestInFlightLimitScalesWithPoolWithinBounds(t *testing.T) {
	for _, tc := range []struct {
		conns int32
		want  int
	}{{4, 64}, {8, 64}, {16, 128}, {32, 256}, {200, 512}} {
		cfg, err := pgxpool.ParseConfig("postgres://lab@127.0.0.1/lindm")
		if err != nil {
			t.Fatal(err)
		}
		cfg.MaxConns = tc.conns
		pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		if got := inFlightLimit(pool); got != tc.want {
			t.Errorf("pool %d: in-flight %d want %d", tc.conns, got, tc.want)
		}
		pool.Close()
	}
	if inFlightLimit(nil) != minInFlight {
		t.Error("nil pool must use the minimum")
	}
}

// Device traffic saturating admission leaves admin-console headroom, and
// rejected requests release nothing they did not take.
func TestAdminAdmissionReserve(t *testing.T) {
	s := &Service{inFlightMax: 2}
	device := context.Background()
	for range 2 {
		if err := s.acquire(device); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.acquire(device); err == nil {
		t.Fatal("device admission exceeded its limit")
	}
	var admin context.Context
	withAdminAdmission(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { admin = r.Context() })).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/", nil))
	for range adminReserve {
		if err := s.acquire(admin); err != nil {
			t.Fatalf("admin reserve not available: %v", err)
		}
	}
	if err := s.acquire(admin); err == nil {
		t.Fatal("admin admission exceeded its reserve")
	}
	for range 2 + adminReserve {
		s.release()
	}
	if got := s.inFlight.Load(); got != 0 {
		t.Fatalf("in-flight count leaked: %d", got)
	}
	cancelled, cancel := context.WithCancel(device)
	cancel()
	if err := s.acquire(cancelled); !errors.Is(err, context.Canceled) || s.inFlight.Load() != 0 {
		t.Fatalf("cancelled acquire: %v", err)
	}
}
