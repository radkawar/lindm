package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"runtime/pprof"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"

	configv1 "lindm/gen/lindm/config/v1"
)

func TestProfilingDisabledAndRejected(t *testing.T) {
	previous := runtime.SetMutexProfileFraction(-1)
	p, err := newProfiler(t.Context(), nil)
	if err != nil || p != nil {
		t.Fatalf("disabled profiler = %v, %v", p, err)
	}
	for _, address := range []string{"0.0.0.0", "::", "192.0.2.1", "localhost"} {
		cfg := profilingTestConfig(19090, 1)
		cfg.Listener.Address = address
		if p, err := newProfiler(t.Context(), cfg); err == nil || p != nil {
			t.Fatalf("unsafe listener %q accepted", address)
		}
	}
	if got := runtime.SetMutexProfileFraction(-1); got != previous {
		t.Fatalf("disabled or rejected profiler changed sampling: %d to %d", previous, got)
	}
}

func TestProfilingBindFailureDoesNotEnableSampling(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := listener.Close(); err != nil {
			t.Error(err)
		}
	})
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatal("listener is not TCP")
	}
	previous := runtime.SetMutexProfileFraction(-1)
	if p, err := newProfiler(t.Context(), profilingTestConfig(uint32(address.Port), 1)); err == nil || p != nil {
		t.Fatal("occupied profiling port accepted")
	}
	if got := runtime.SetMutexProfileFraction(-1); got != previous {
		t.Fatal("bind failure changed runtime sampling")
	}
}

func TestProfilingPrivateMux(t *testing.T) {
	p, _ := startTestProfiler(t, 1)
	for _, test := range []struct {
		path, method, host, origin string
		status                     int
	}{
		{path: "/debug/pprof/", status: http.StatusNotFound},
		{path: "/debug/pprof/heap", status: http.StatusNotFound},
		{path: "/debug/pprof/cmdline", status: http.StatusNotFound},
		{path: "/debug/pprof/trace", status: http.StatusNotFound},
		{path: "/readyz", status: http.StatusNotFound},
		{path: "/debug/pprof/profile?seconds=999", status: http.StatusBadRequest},
		{path: "/debug/pprof/block?debug=1", status: http.StatusBadRequest},
		{path: "/debug/pprof/profile", method: http.MethodPost, status: http.StatusMethodNotAllowed},
		{path: "/debug/pprof/profile", method: http.MethodHead, status: http.StatusMethodNotAllowed},
		{path: "/debug/pprof/block", host: "attacker.example", status: http.StatusForbidden},
		{path: "/debug/pprof/block", origin: "https://attacker.example", status: http.StatusForbidden},
	} {
		t.Run(test.path+test.method+test.host+test.origin, func(t *testing.T) {
			method := test.method
			if method == "" {
				method = http.MethodGet
			}
			req := httptest.NewRequest(method, "http://"+p.server.Addr+test.path, nil)
			if test.host != "" {
				req.Host = test.host
			}
			if test.origin != "" {
				req.Header.Set("Origin", test.origin)
			}
			response := httptest.NewRecorder()
			p.server.Handler.ServeHTTP(response, req)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d", response.Code, test.status)
			}
		})
	}
	for _, mux := range []*http.ServeMux{http.DefaultServeMux, http.NewServeMux()} {
		for _, path := range []string{"profile", "mutex", "block"} {
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/debug/pprof/"+path, nil))
			if response.Code != http.StatusNotFound {
				t.Fatal("private profiler leaked into another mux")
			}
		}
	}
}

func TestProfilingRealRuntimeOutputs(t *testing.T) {
	p, _ := startTestProfiler(t, 1)
	work, cancel := context.WithCancel(t.Context())
	var workers sync.WaitGroup
	var mutex sync.Mutex
	for range 2 {
		workers.Go(func() {
			for work.Err() == nil {
				mutex.Lock()
				runtime.Gosched()
				mutex.Unlock()
			}
		})
	}
	t.Cleanup(func() { cancel(); workers.Wait() })
	client := profilingTestClient(t)
	for _, name := range []string{"profile", "mutex", "block"} {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+p.server.Addr+"/debug/pprof/"+name, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, 8<<20))
		closeErr := response.Body.Close()
		if err := errors.Join(readErr, closeErr); err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/octet-stream" || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("profile %s response = %d %v", name, response.StatusCode, response.Header)
		}
		assertRuntimeProfile(t, name, data)
	}
}

func TestProfilingCancellationRestoresRuntime(t *testing.T) {
	previous := runtime.SetMutexProfileFraction(7)
	t.Cleanup(func() { runtime.SetMutexProfileFraction(previous) })
	p, stop := startTestProfiler(t, 60)
	client := profilingTestClient(t)
	captureDone := make(chan error, 1)
	go func() {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+p.server.Addr+"/debug/pprof/profile", nil)
		if err != nil {
			captureDone <- err
			return
		}
		response, err := client.Do(req)
		if err != nil {
			captureDone <- err
			return
		}
		if response.StatusCode != http.StatusOK {
			captureDone <- errors.Join(errors.New("CPU capture did not return HTTP 200"), response.Body.Close())
			return
		}
		_, readErr := io.Copy(io.Discard, response.Body)
		captureDone <- errors.Join(readErr, response.Body.Close())
	}()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	// Observe admission without making a competing profile request: probing
	// /mutex before CPU admission can itself take the only slot and reject CPU.
	for len(p.inFlight) == 0 {
		select {
		case err := <-captureDone:
			t.Fatalf("CPU capture exited before admission: %v", err)
		case <-deadline.C:
			t.Fatal("CPU capture did not start")
		case <-ticker.C:
		}
	}
	response := httptest.NewRecorder()
	p.server.Handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://"+p.server.Addr+"/debug/pprof/mutex", nil))
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("concurrent capture status = %d, want 429", response.Code)
	}
	stop()
	select {
	case err := <-captureDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("active CPU capture survived cancellation")
	}
	if got := runtime.SetMutexProfileFraction(-1); got != 7 {
		t.Fatalf("mutex sampling not restored: %d", got)
	}
	if err := pprof.StartCPUProfile(io.Discard); err != nil {
		t.Fatalf("cancelled listener retained CPU profiler: %v", err)
	}
	pprof.StopCPUProfile()
	connection, err := net.DialTimeout("tcp", p.server.Addr, time.Second)
	if err == nil {
		if err := connection.Close(); err != nil {
			t.Fatal(err)
		}
		t.Fatal("profiling listener survived cancellation")
	}
}

func profilingTestConfig(port uint32, seconds uint32) *configv1.ProfilingConfig {
	return &configv1.ProfilingConfig{
		Listener:          &configv1.ListenerConfig{Address: "127.0.0.1", Port: port},
		CpuProfileSeconds: seconds, MutexProfileFraction: 1, BlockProfileRateNs: 1,
	}
}

func startTestProfiler(t *testing.T, seconds uint32) (*profiler, func()) {
	t.Helper()
	reservation, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address, ok := reservation.Addr().(*net.TCPAddr)
	closeErr := reservation.Close()
	if !ok || closeErr != nil {
		t.Fatalf("reserve TCP port: %v", closeErr)
	}
	ctx, cancel := context.WithCancel(t.Context())
	p, err := newProfiler(ctx, profilingTestConfig(uint32(address.Port), seconds))
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- p.run(ctx) }()
	var once sync.Once
	stop := func() {
		t.Helper()
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(5 * time.Second):
				t.Error("profiler failed to stop within five seconds")
			}
		})
	}
	t.Cleanup(stop)
	return p, stop
}

func profilingTestClient(t *testing.T) *http.Client {
	t.Helper()
	transport := &http.Transport{ResponseHeaderTimeout: 4 * time.Second}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}

// Runtime profiles are gzip-compressed pprof protobufs. Decode every wire field,
// requiring sample types and the format's string table, rather than accepting a
// status-only or gzip-header-only response. No profiler mock is involved.
func assertRuntimeProfile(t *testing.T, name string, data []byte) {
	t.Helper()
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("%s profile gzip: %v", name, err)
	}
	decoded, readErr := io.ReadAll(io.LimitReader(reader, 16<<20))
	if err := errors.Join(readErr, reader.Close()); err != nil {
		t.Fatal(err)
	}
	var sampleTypes, samples, strings int
	var duration uint64
	for len(decoded) != 0 {
		number, kind, n := protowire.ConsumeTag(decoded)
		if n < 0 {
			t.Fatal("invalid profile protobuf tag")
		}
		decoded = decoded[n:]
		n = protowire.ConsumeFieldValue(number, kind, decoded)
		if n < 0 {
			t.Fatal("invalid profile protobuf value")
		}
		switch number {
		case 1:
			sampleTypes++
		case 2:
			samples++
		case 6:
			strings++
		case 10:
			duration, _ = protowire.ConsumeVarint(decoded)
		}
		decoded = decoded[n:]
	}
	if sampleTypes == 0 || strings == 0 || samples == 0 {
		t.Fatalf("%s profile missing runtime samples/types/strings: %d/%d/%d", name, samples, sampleTypes, strings)
	}
	if name == "profile" && (duration == 0 || duration > uint64(3*time.Second)) {
		t.Fatalf("CPU capture duration was not bounded: %d ns", duration)
	}
}
