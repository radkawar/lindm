// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"testing"

	"buf.build/go/protovalidate"

	resourcev1 "lindm/gen/lindm/resource/v1"
)

func TestAcceptanceFailureCannotReportCompleted(t *testing.T) {
	visited := false
	result, err := RunAcceptanceGuest(t.Context(), AcceptanceGuestOptions{}, func(context.Context, *AcceptanceGuest) error {
		visited = true
		return nil
	})
	if err == nil || result == nil || result.Completed || result.Failure == "" || result.FinishedAt.Before(result.StartedAt) || visited {
		t.Fatalf("invalid acceptance escaped as success or visited guest: result=%+v error=%v visited=%v", result, err, visited)
	}
}

func TestAcceptanceClosedHandleCannotOperateOnGuest(t *testing.T) {
	g := &AcceptanceGuest{closed: true, enrolled: true, probeReady: true}
	if _, err := g.Run(t.Context(), "true", nil); err == nil {
		t.Fatal("closed guest accepted native command")
	}
	if _, err := g.Forward(t.Context(), "127.0.0.1:0", "127.0.0.1:1"); err == nil {
		t.Fatal("closed guest accepted a forward")
	}
	if _, err := g.Enroll(t.Context(), nil, "grant", []byte("private")); err == nil {
		t.Fatal("closed guest accepted enrollment")
	}
	if _, err := g.Observe(t.Context(), nil); err == nil {
		t.Fatal("closed guest accepted observation")
	}
	if _, err := g.PrepareServiceProbe(t.Context()); err == nil {
		t.Fatal("closed guest accepted probe creation")
	}
	if err := g.VerifyServiceEffect(t.Context(), true, true); err == nil {
		t.Fatal("closed guest accepted native effect proof")
	}
}

func TestAcceptanceUnchangedBaselineIsNotNativeEffect(t *testing.T) {
	g := &AcceptanceGuest{vm: &guestVM{}, probeReady: true, evidence: new(AcceptanceGuestEvidence)}
	if err := g.VerifyServiceEffect(t.Context(), false, false); err == nil {
		t.Fatal("unchanged inactive/disabled baseline was accepted as a profile effect")
	}
	if g.evidence.ServiceEffect {
		t.Fatal("rejected native effect changed evidence")
	}
}

func TestAcceptanceServiceProbeIsManageable(t *testing.T) {
	desired := &resourcev1.SystemdServiceDesired{
		Unit:       AcceptanceServiceProbeUnit,
		Runtime:    resourcev1.ServiceRuntimeState_SERVICE_RUNTIME_STATE_ACTIVE,
		Enablement: resourcev1.ServiceEnablement_SERVICE_ENABLEMENT_ENABLED,
	}
	if err := protovalidate.Validate(desired); err != nil {
		t.Fatalf("acceptance probe is not an admissible customer service: %v", err)
	}
}
