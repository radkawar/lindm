package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"runtime"
	"runtime/pprof"
	"time"

	"buf.build/go/protovalidate"

	configv1 "lindm/gen/lindm/config/v1"
	"lindm/internal/config"
)

// profiler owns the private listener and process-wide runtime sampling. Run owns
// exactly one profiler; nothing registers handlers on http.DefaultServeMux.
type profiler struct {
	server   *http.Server
	listener net.Listener
	cancel   context.CancelFunc
	inFlight <-chan struct{}
	mutex    int
	block    int
}

func newProfiler(ctx context.Context, cfg *configv1.ProfilingConfig) (*profiler, error) {
	if cfg == nil {
		return nil, nil
	}
	validator, err := protovalidate.New(protovalidate.WithMessages(cfg))
	if err != nil {
		return nil, fmt.Errorf("compile profiling configuration: %w", err)
	}
	if err := validator.Validate(cfg); err != nil {
		return nil, fmt.Errorf("validate profiling configuration: %w", err)
	}
	address := config.Address(cfg.GetListener())
	listener, err := new(net.ListenConfig).Listen(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("bind private profiling listener: %w", err)
	}
	requests, cancel := context.WithCancel(ctx)
	duration := time.Duration(cfg.GetCpuProfileSeconds()) * time.Second
	mux := http.NewServeMux()
	mux.HandleFunc("GET /debug/pprof/profile", func(w http.ResponseWriter, r *http.Request) {
		profileHeaders(w, "cpu")
		if err := pprof.StartCPUProfile(w); err != nil {
			http.Error(w, "CPU profiler unavailable", http.StatusConflict)
			return
		}
		defer pprof.StopCPUProfile()
		timer := time.NewTimer(duration)
		defer timer.Stop()
		select {
		case <-r.Context().Done():
		case <-timer.C:
		}
	})
	for _, name := range []string{"mutex", "block"} {
		mux.HandleFunc("GET /debug/pprof/"+name, func(w http.ResponseWriter, _ *http.Request) {
			profileHeaders(w, name)
			if err := pprof.Lookup(name).WriteTo(w, 0); err != nil {
				slog.Warn("write private runtime profile", "profile", name, "error", err)
			}
		})
	}
	// One profile request at a time bounds expensive runtime work without queuing.
	// Exact Host and Origin checks prevent browser-driven DNS rebinding access;
	// this remains an operator-only local surface, not an authentication scheme.
	slot := make(chan struct{}, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Host != address || len(r.Header.Values("Origin")) != 0 {
			http.Error(w, "private profiling listener only", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "GET required", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			http.Error(w, "profile parameters are configured by the operator", http.StatusBadRequest)
			return
		}
		select {
		case slot <- struct{}{}:
			defer func() { <-slot }()
		default:
			http.Error(w, "profile capture already active", http.StatusTooManyRequests)
			return
		}
		mux.ServeHTTP(w, r)
	})
	return &profiler{
		server: &http.Server{
			Addr: address, Handler: handler,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       5 * time.Second,
			WriteTimeout:      duration + 5*time.Second,
			IdleTimeout:       5 * time.Second,
			MaxHeaderBytes:    4096,
			BaseContext:       func(net.Listener) context.Context { return requests },
		},
		listener: listener, cancel: cancel,
		inFlight: slot,
		mutex:    int(cfg.GetMutexProfileFraction()), block: int(cfg.GetBlockProfileRateNs()),
	}, nil
}

func profileHeaders(w http.ResponseWriter, name string) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.pprof"`)
}

func (p *profiler) run(ctx context.Context) error {
	previousMutex := runtime.SetMutexProfileFraction(p.mutex)
	runtime.SetBlockProfileRate(p.block)
	defer runtime.SetMutexProfileFraction(previousMutex)
	// The runtime has no block-rate getter. This composition root is its sole
	// owner and returns it to the disabled process baseline after every exit.
	defer runtime.SetBlockProfileRate(0)
	defer p.cancel()
	stopped := make(chan error, 1)
	go func() { stopped <- p.server.Serve(p.listener) }()
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-stopped:
		p.cancel()
		return errors.Join(profilingServeError(serveErr), shutdown(p.server))
	}
	// Cancel active CPU captures before draining, rather than waiting for the
	// configured capture duration. Shutdown also bounds slow profile readers.
	p.cancel()
	shutdownErr := shutdown(p.server)
	serveErr = <-stopped
	return errors.Join(profilingServeError(serveErr), shutdownErr)
}

func profilingServeError(err error) error {
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return fmt.Errorf("serve private profiling listener: %w", err)
}
