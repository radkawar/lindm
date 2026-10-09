//go:build linux

package vmlab

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"lindm/internal/devlab"
)

type VMDispatchHoldEvidence struct {
	Origin                     string    `json:"origin"`
	StartedAt                  time.Time `json:"started_at"`
	FinishedAt                 time.Time `json:"finished_at"`
	EndReason                  string    `json:"end_reason"`
	AssignmentBefore           string    `json:"assignment_before"`
	AssignmentAfter            string    `json:"assignment_after"`
	BrowserAssignmentsObserved bool      `json:"browser_assignments_observed"`
}

func holdDispatchConsole(ctx, parent context.Context, detachCancellation func() bool, options VMDispatchOptions, control *vmControlPlane, fixture *devlab.AuthorityFixture, result *VMDispatchResult) error {
	if options.Hold == 0 {
		return nil
	}
	// Retire the automated owner's session before a potentially long browser
	// inspection, then obtain a fresh normal session for revocation afterward.
	if err := control.session.Close(ctx); err != nil {
		return err
	}
	if !detachCancellation() {
		return ctx.Err()
	}
	result.Hold = &VMDispatchHoldEvidence{Origin: "https://localhost:18444", StartedAt: time.Now().UTC()}
	directory := devlab.FixturePath(options.Repository)
	if _, err := fmt.Fprintf(options.Progress, "DISPATCH HOLD READY\nadmin origin: https://localhost:18444\nTLS/browser trust: %s (same development CA; no TLS bypass)\nowner sign-in: Keycloak username owner; password in %s\ndevice: %s\nhold: %s; timeout or SIGINT resumes revocation and cleanup\n", filepath.Join(directory, "transport-ca.crt"), filepath.Join(directory, "owner-password"), result.DeviceID, options.Hold); err != nil {
		return err
	}
	timer := time.NewTimer(options.Hold)
	defer timer.Stop()
	select {
	case <-timer.C:
		result.Hold.EndReason = "timeout"
	case <-parent.Done():
		result.Hold.EndReason = "interrupted"
	case <-ctx.Done():
		return ctx.Err()
	}
	result.Hold.FinishedAt = time.Now().UTC()
	session, err := fixture.OpenOwnerSession(ctx)
	if err != nil {
		return err
	}
	control.session = session
	return nil
}
