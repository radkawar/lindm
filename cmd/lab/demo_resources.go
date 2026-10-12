package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"connectrpc.com/connect"

	adminv1 "lindm/gen/lindm/admin/v1"
)

// demoResourcePoll bounds how quickly a held demo reports a changed product
// resource outcome. Each poll opens one fresh bounded owner session.
const demoResourcePoll = 30 * time.Second

// demoResourceRow is the product's public report of one assigned resource row on
// one device: identity, server disposition and the latest device-signed status.
// Desired values are omitted because they can reference secrets.
type demoResourceRow struct {
	Kind         string `json:"kind"`
	Key          string `json:"key"`
	Disposition  string `json:"disposition"`
	Compliance   string `json:"compliance"`
	Reason       string `json:"reason,omitempty"`
	Execution    string `json:"execution,omitempty"`
	Failure      string `json:"failure,omitempty"`
	Refusal      string `json:"refusal,omitempty"`
	Verification string `json:"verification,omitempty"`
	Verified     bool   `json:"verified"`
}

type demoResourceRecord struct {
	DeviceID     string            `json:"deviceId"`
	AssignmentID string            `json:"assignmentId,omitempty"`
	ObservedAt   time.Time         `json:"observedAt"`
	Resources    []demoResourceRow `json:"resources"`
}

func demoResourceRows(state *adminv1.GetDeviceResourceStateResponse) []demoResourceRow {
	rows := make([]demoResourceRow, 0, len(state.GetResources()))
	for _, resource := range state.GetResources() {
		status := resource.GetLatestAction().GetStatus()
		row := demoResourceRow{
			Kind:        strings.TrimPrefix(resource.GetDesired().GetRef().GetKind().String(), "RESOURCE_KIND_"),
			Key:         resource.GetDesired().GetRef().GetCanonicalKey(),
			Disposition: strings.TrimPrefix(resource.GetDisposition().String(), "RESOURCE_DISPOSITION_"),
			Compliance:  strings.TrimPrefix(resource.GetCompliance().String(), "RESOURCE_COMPLIANCE_"),
			Reason:      resource.GetReason(),
			Verified:    resource.GetLastVerifiedAt() != nil,
		}
		if status != nil {
			row.Execution = strings.TrimPrefix(status.GetState().String(), "RESOURCE_EXECUTION_STATE_")
			if failure := status.GetFailure().String(); failure != "RESOURCE_EXECUTION_FAILURE_NONE" {
				row.Failure = strings.TrimPrefix(failure, "RESOURCE_EXECUTION_FAILURE_")
			}
			if refusal := status.GetAdmissionRefusal(); refusal != nil {
				row.Refusal = strings.TrimPrefix(refusal.GetReason().String(), "RESOURCE_ADMISSION_REFUSAL_REASON_")
			}
			if verification := status.GetVerification(); verification != nil {
				row.Verification = strings.TrimPrefix(verification.GetDisposition().String(), "VERIFICATION_DISPOSITION_")
			}
		}
		rows = append(rows, row)
	}
	return rows
}

func demoResourcesText(rows []demoResourceRow) string {
	if len(rows) == 0 {
		return "no assigned resources"
	}
	parts := make([]string, 0, len(rows))
	for _, row := range rows {
		text := row.Kind + " " + row.Key + " " + row.Disposition + "/" + row.Compliance
		for _, detail := range []string{row.Reason, row.Failure, row.Refusal} {
			if detail != "" {
				text += " " + detail
			}
		}
		parts = append(parts, text)
	}
	return strings.Join(parts, "; ")
}

// watchResources reports each device's product resource outcomes while the demo
// is held, recording every changed report as new public evidence. It never
// treats a report as convergence: the product's own disposition is shown as is.
func (r *demoRun) watchResources(ctx context.Context) error {
	last := make(map[string][]demoResourceRow)
	sequence := make(map[string]int)
	for {
		if err := r.reportResources(ctx, last, sequence); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(demoResourcePoll):
		}
	}
}

func (r *demoRun) reportResources(ctx context.Context, last map[string][]demoResourceRow, sequence map[string]int) (err error) {
	owner, err := r.controller.Fixture.OpenOwnerSession(ctx)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, closeDemoSession(owner)) }()
	for _, bound := range r.state.Bindings {
		access := r.access.Devices[bound.Key]
		if access == nil {
			return fmt.Errorf("device %s has no ready identity", bound.Key)
		}
		response, err := owner.Admin.GetDeviceResourceState(ctx, connect.NewRequest(&adminv1.GetDeviceResourceStateRequest{DeviceId: access.DeviceID}))
		if err != nil {
			return fmt.Errorf("device %s resource state: %w", bound.Key, err)
		}
		rows := demoResourceRows(response.Msg)
		if previous, seen := last[bound.Key]; seen && slices.Equal(previous, rows) {
			continue
		}
		last[bound.Key] = rows
		sequence[bound.Key]++
		record := demoResourceRecord{DeviceID: access.DeviceID, AssignmentID: response.Msg.GetAssignment().GetAssignmentId(), ObservedAt: time.Now().UTC(), Resources: rows}
		if err := publishDemoJSON(filepath.Join(r.options.evidence, fmt.Sprintf("resources-%s-%03d.json", bound.Key, sequence[bound.Key])), record, 0400); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(r.stdout, "Resources %s: %s\n", bound.Key, demoResourcesText(rows)); err != nil {
			return err
		}
	}
	return nil
}
