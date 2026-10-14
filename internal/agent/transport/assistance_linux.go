// SPDX-License-Identifier: Apache-2.0

//go:build linux

package transport

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"time"

	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/gen/lindm/agent/v1/agentv1connect"
	devicev1 "lindm/gen/lindm/device/v1"
)

const (
	assistanceIdleInterval   = 15 * time.Second
	assistanceActiveInterval = time.Second
	assistanceCycleTimeout   = 30 * time.Second
)

// assistanceLoop relays complete assistance state between the server and the
// root executor. It holds no authority: directives are passed to the executor
// at most once, so a failed server exchange never refreshes the executor's
// reauthorization window with stale directives.
type assistanceLoop struct {
	executor agentv1connect.ExecutorServiceClient
	cache    connectionCache
	gate     authorityGate
	// fresh are the last server directives not yet delivered to the executor.
	fresh   []*agentv1.AssistanceDirective
	active  bool
	lastErr string
}

func startAssistance(parent context.Context, executor agentv1connect.ExecutorServiceClient, gate authorityGate) func() {
	loop := &assistanceLoop{executor: executor, gate: gate}
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer loop.cache.Close()
		for ctx.Err() == nil {
			err := loop.cycle(ctx)
			if ctx.Err() != nil {
				return
			}
			loop.log(err)
			timer := time.NewTimer(loop.delay())
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

// cycle is one pipeline tick: reports = executor(fresh directives), then
// directives = server(session epoch, reports).
func (l *assistanceLoop) cycle(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, assistanceCycleTimeout)
	defer cancel()
	directives := l.fresh
	l.fresh = nil
	local, err := rpc(ctx, l.executor.SyncAssistance, &agentv1.SyncAssistanceRequest{Directives: directives})
	if err != nil {
		l.active = openDirectives(directives)
		return fmt.Errorf("sync executor assistance: %w", err)
	}
	if err := validateManagementMessage(local); err != nil {
		l.active = openDirectives(directives)
		return fmt.Errorf("invalid executor assistance reports: %w", err)
	}
	l.active = openReports(local.GetReports())
	authority, err := establish(ctx, l.executor, &l.cache, l.gate)
	if err != nil {
		return fmt.Errorf("establish assistance session: %w", err)
	}
	response, err := rpc(ctx, authority.servers.device.SyncAssistance, &devicev1.SyncAssistanceRequest{SessionEpoch: authority.epoch, Reports: local.GetReports(), Policy: local.GetPolicy()})
	if err != nil {
		return fmt.Errorf("sync server assistance: %w", err)
	}
	if err := validateManagementMessage(response); err != nil {
		return fmt.Errorf("invalid server assistance directives: %w", err)
	}
	l.fresh = response.GetDirectives()
	l.active = l.active || openDirectives(l.fresh)
	return nil
}

// delay polls every second while any session is open in either direction,
// otherwise every 15 s with ±10% jitter that affects scheduling only.
func (l *assistanceLoop) delay() time.Duration {
	if l.active {
		return assistanceActiveInterval
	}
	return assistanceIdleInterval - assistanceIdleInterval/10 + time.Duration(rand.Int64N(int64(assistanceIdleInterval/5)))
}

// log reports a changed failure once; an idle device whose server has no
// assistance configured does not warn every poll.
func (l *assistanceLoop) log(err error) {
	text := ""
	if err != nil {
		text = err.Error()
	}
	if text == l.lastErr {
		return
	}
	l.lastErr = text
	if err != nil {
		slog.Warn("remote assistance synchronization incomplete", "error", err)
	}
}

func openDirectives(directives []*agentv1.AssistanceDirective) bool {
	for _, directive := range directives {
		if !directive.GetTerminate() {
			return true
		}
	}
	return false
}

func openReports(reports []*agentv1.AssistanceReport) bool {
	for _, report := range reports {
		if report.GetPhase() != agentv1.AssistancePhase_ASSISTANCE_PHASE_ENDED {
			return true
		}
	}
	return false
}
