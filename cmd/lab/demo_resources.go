// SPDX-License-Identifier: Apache-2.0

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
	Detail       string `json:"detail,omitempty"`
	Verification string `json:"verification,omitempty"`
	Verified     bool   `json:"verified"`
}

// demoCapabilityState is the device page's capability view: the server's grant
// with its scopes, the latest signed version, and the executor's own report.
type demoCapabilityState struct {
	Granted             []string `json:"granted"`
	IssuedVersion       uint64   `json:"issuedVersion"`
	IssuanceUnavailable string   `json:"issuanceUnavailable,omitempty"`
	ReportedState       string   `json:"reportedState,omitempty"`
	ReportedVersion     uint64   `json:"reportedVersion"`
	Reported            []string `json:"reported"`
}

type demoResourceRecord struct {
	DeviceID     string               `json:"deviceId"`
	AssignmentID string               `json:"assignmentId,omitempty"`
	ObservedAt   time.Time            `json:"observedAt"`
	Capabilities *demoCapabilityState `json:"capabilities,omitempty"`
	Resources    []demoResourceRow    `json:"resources"`
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
				row.Detail = refusal.GetDetail()
			}
			if verification := status.GetVerification(); verification != nil {
				row.Verification = strings.TrimPrefix(verification.GetDisposition().String(), "VERIFICATION_DISPOSITION_")
			}
		}
		rows = append(rows, row)
	}
	return rows
}

// demoCapabilities reduces the device page's capability state to public text:
// catalogue names, grant scopes, versions and closed status details only.
func demoCapabilities(state *adminv1.DeviceCapabilityState) *demoCapabilityState {
	if state == nil {
		return nil
	}
	view := &demoCapabilityState{
		IssuedVersion:       state.GetIssuedVersion(),
		IssuanceUnavailable: state.GetIssuanceUnavailableReason(),
		ReportedVersion:     state.GetReported().GetAppliedVersion(),
		Granted:             make([]string, 0, len(state.GetGranted())),
		Reported:            make([]string, 0, len(state.GetReported().GetCapabilities())),
	}
	for _, grant := range state.GetGranted() {
		sources := make([]string, 0, len(grant.GetSources()))
		for _, source := range grant.GetSources() {
			switch {
			case source.GetDeployment():
				sources = append(sources, "deployment")
			case source.GetStaticGroupId() != "":
				sources = append(sources, "static_group:"+source.GetStaticGroupId())
			case source.GetDynamicGroupId() != "":
				sources = append(sources, "dynamic_group:"+source.GetDynamicGroupId())
			}
		}
		view.Granted = append(view.Granted, strings.TrimPrefix(grant.GetCapability().String(), "MANAGEMENT_CAPABILITY_")+" ("+strings.Join(sources, ", ")+")")
	}
	if reported := state.GetReported(); reported != nil {
		view.ReportedState = strings.TrimPrefix(reported.GetState().String(), "CAPABILITY_POLICY_STATE_")
		for _, capability := range reported.GetCapabilities() {
			text := strings.TrimPrefix(capability.GetCapability().String(), "MANAGEMENT_CAPABILITY_") + " " + strings.TrimPrefix(capability.GetStatus().String(), "CAPABILITY_STATUS_")
			if capability.GetDetail() != "" {
				text += " " + capability.GetDetail()
			}
			view.Reported = append(view.Reported, text)
		}
	}
	return view
}

func demoCapabilitiesText(view *demoCapabilityState) string {
	if view == nil {
		return "not reported"
	}
	text := fmt.Sprintf("granted [%s] issued v%d", strings.Join(view.Granted, "; "), view.IssuedVersion)
	if view.IssuanceUnavailable != "" {
		text += " unavailable " + view.IssuanceUnavailable
	}
	if view.ReportedState != "" {
		text += fmt.Sprintf("; executor %s v%d [%s]", view.ReportedState, view.ReportedVersion, strings.Join(view.Reported, "; "))
	}
	return text
}

func demoResourcesText(rows []demoResourceRow) string {
	if len(rows) == 0 {
		return "no assigned resources"
	}
	parts := make([]string, 0, len(rows))
	for _, row := range rows {
		text := row.Kind + " " + row.Key + " " + row.Disposition + "/" + row.Compliance
		for _, detail := range []string{row.Reason, row.Failure, row.Refusal, row.Detail} {
			if detail != "" {
				text += " " + detail
			}
		}
		parts = append(parts, text)
	}
	return strings.Join(parts, "; ")
}

// demoDeviceReport is the last published report for one device.
type demoDeviceReport struct {
	rows         []demoResourceRow
	capabilities string
}

// watchResources reports each device's product resource outcomes and capability
// state while the demo is held, recording every changed report as new public
// evidence. It never treats a report as convergence: the product's own
// disposition is shown as is.
func (r *demoRun) watchResources(ctx context.Context) error {
	last := make(map[string]demoDeviceReport)
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

func (r *demoRun) reportResources(ctx context.Context, last map[string]demoDeviceReport, sequence map[string]int) (err error) {
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
		device, err := owner.Admin.GetDevice(ctx, connect.NewRequest(&adminv1.GetDeviceRequest{DeviceId: access.DeviceID}))
		if err != nil {
			return fmt.Errorf("device %s capabilities: %w", bound.Key, err)
		}
		rows := demoResourceRows(response.Msg)
		capabilities := demoCapabilities(device.Msg.GetCapabilities())
		report := demoDeviceReport{rows: rows, capabilities: demoCapabilitiesText(capabilities)}
		if previous, seen := last[bound.Key]; seen && slices.Equal(previous.rows, report.rows) && previous.capabilities == report.capabilities {
			continue
		}
		last[bound.Key] = report
		sequence[bound.Key]++
		record := demoResourceRecord{DeviceID: access.DeviceID, AssignmentID: response.Msg.GetAssignment().GetAssignmentId(), ObservedAt: time.Now().UTC(), Capabilities: capabilities, Resources: rows}
		if err := publishDemoJSON(filepath.Join(r.options.evidence, fmt.Sprintf("resources-%s-%03d.json", bound.Key, sequence[bound.Key])), record, 0400); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(r.stdout, "Capabilities %s: %s\nResources %s: %s\n", bound.Key, report.capabilities, bound.Key, demoResourcesText(rows)); err != nil {
			return err
		}
	}
	return nil
}
