// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"context"
	"errors"
	"slices"
	"time"

	authv1 "lindm/gen/lindm/auth/v1"
	"lindm/internal/devlab"
)

const (
	assistanceViewRole        = "assistance-view-only"
	assistanceControlRole     = "assistance-control-only"
	assistanceViewControlRole = "assistance-view-control"
)

func assistanceQualificationRoles() []*authv1.RoleDefinition {
	return []*authv1.RoleDefinition{
		{Name: assistanceNoClipboardRole, Permissions: []string{"fleet.read", "remote_assistance.view", "remote_assistance.control", "remote_assistance.keyboard", "remote_assistance.display", "remote_assistance.message", "remote_assistance.files"}},
		{Name: assistanceNoFilesRole, Permissions: []string{"fleet.read", "remote_assistance.view", "remote_assistance.control", "remote_assistance.keyboard", "remote_assistance.display", "remote_assistance.message", "remote_assistance.clipboard"}},
		// Keep keyboard unchanged when control is revoked, so another capability's
		// withdrawal cannot masquerade as proof of the control-permission fence.
		{Name: assistanceViewRole, Permissions: []string{"fleet.read", "remote_assistance.view", "remote_assistance.keyboard"}},
		{Name: assistanceControlRole, Permissions: []string{"fleet.read", "remote_assistance.control"}},
		{Name: assistanceViewControlRole, Permissions: []string{"fleet.read", "remote_assistance.view", "remote_assistance.control", "remote_assistance.keyboard"}},
		// Archive authority never implies live assistance, and recording a
		// session never implies retrieving it.
		{Name: assistanceArchiveRole, Permissions: []string{"fleet.read", "remote_assistance.recordings.read"}},
		{Name: assistanceNoRecordingsRole, Permissions: []string{"fleet.read", "remote_assistance.view", "remote_assistance.control", "remote_assistance.record"}},
	}
}

type assistanceModeDenial struct {
	Actor         *assistanceActor `json:"actor"`
	RequestID     string           `json:"request_id"`
	DeviceID      string           `json:"device_id"`
	Mode          string           `json:"mode"`
	Code          string           `json:"code"`
	Reason        string           `json:"reason"`
	HTTPStatus    int              `json:"http_status"`
	ObservedAt    time.Time        `json:"observed_at"`
	ControlOption bool             `json:"control_option"`
	RequestForm   bool             `json:"request_form"`
}

type assistanceModeAuthorityEvidence struct {
	Before        *assistanceActor      `json:"before"`
	After         *assistanceActor      `json:"after,omitempty"`
	ViewDenial    *assistanceModeDenial `json:"control_only_view_denial,omitempty"`
	ControlDenial *assistanceModeDenial `json:"view_only_control_denial,omitempty"`
	ChangedBy     string                `json:"changed_by,omitempty"`
}

func (r *assistanceRun) modeAuthorityScenario(ctx context.Context, fixture *devlab.AuthorityFixture, options VMAssistanceOptions, private string, spec assistanceScenarioSpec) (err error) {
	var viewDenial *assistanceModeDenial
	role := assistanceViewControlRole
	if spec.name == "authority-view" {
		role = assistanceViewRole
		viewDenial, err = r.controlOnlyDenial(ctx, fixture, options, private)
		if err != nil {
			return err
		}
	}
	browser, err := openAssistanceOperator(ctx, fixture, options, private, spec.name, role)
	if err != nil {
		return err
	}
	previous := r.browser
	r.browser = browser
	defer func() {
		r.browser = previous
		err = errors.Join(err, browser.Close())
		if options.PersistentDir != "" {
			err = errors.Join(err, retireAssistanceOperator(ctx, fixture, browser.accountID))
		}
	}()
	var controlDenial *assistanceModeDenial
	if spec.name == "authority-view" {
		controlDenial = &assistanceModeDenial{}
		if err := browser.call(ctx, "refuseMode", map[string]any{"deviceId": r.deviceID, "mode": "control"}, controlDenial, time.Minute); err != nil {
			return err
		}
		if err := r.screen.waitNoBanner(ctx, 30*time.Second); err != nil {
			return err
		}
	}
	if err := r.scenario(ctx, spec); err != nil {
		return err
	}
	scenario := r.result.Scenarios[len(r.result.Scenarios)-1]
	scenario.ModeAuthority.ViewDenial, scenario.ModeAuthority.ControlDenial = viewDenial, controlDenial
	return verifyAssistanceModeAuthority(scenario)
}

func (r *assistanceRun) controlOnlyDenial(ctx context.Context, fixture *devlab.AuthorityFixture, options VMAssistanceOptions, private string) (_ *assistanceModeDenial, err error) {
	browser, err := openAssistanceOperator(ctx, fixture, options, private, "authority-control-only", assistanceControlRole)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, browser.Close())
		if options.PersistentDir != "" {
			err = errors.Join(err, retireAssistanceOperator(ctx, fixture, browser.accountID))
		}
	}()
	denial := &assistanceModeDenial{}
	if err := browser.call(ctx, "refuseMode", map[string]any{"deviceId": r.deviceID, "mode": "view"}, denial, time.Minute); err != nil {
		return nil, err
	}
	return denial, r.screen.waitNoBanner(ctx, 30*time.Second)
}

func (r *assistanceRun) prepareModeAuthority(ctx context.Context, scenario *assistanceScenarioEvidence) error {
	if scenario.Name != "authority-view" && scenario.Name != "authority-control" {
		return nil
	}
	scenario.ModeAuthority = &assistanceModeAuthorityEvidence{Before: &assistanceActor{}}
	return r.browser.call(ctx, "identity", nil, scenario.ModeAuthority.Before, 30*time.Second)
}

func (r *assistanceRun) revokeModeControl(ctx context.Context, scenario *assistanceScenarioEvidence) error {
	if err := r.typeNonce(ctx, scenario); err != nil {
		return err
	}
	if err := r.owner.UpdateAssistanceOperator(ctx, &authv1.UpdateAccountRequest{AccountId: scenario.OperatorID, Enabled: true, Role: assistanceViewRole}); err != nil {
		return err
	}
	scenario.ModeAuthority.ChangedBy = r.owner.AccountID
	if _, err := r.waitSession(ctx, scenario, 45*time.Second, "control authority revoked", ended); err != nil {
		return err
	}
	// Account mutation revokes the browser cookie too. Sign in normally with the
	// same authenticator, then inspect the ended record, never reconnect media.
	scenario.ModeAuthority.After = &assistanceActor{}
	return r.browser.call(ctx, "reopen", map[string]any{"deviceId": r.deviceID, "sessionId": scenario.SessionID}, scenario.ModeAuthority.After, time.Minute)
}

func verifyAssistanceModeDenial(denial *assistanceModeDenial, deviceID, mode, role, granted, missing string) error {
	if denial == nil || denial.Actor == nil || !vmValidID(denial.Actor.ID) || denial.Actor.Role != role || denial.Actor.ObservedAt.IsZero() || !slices.Contains(denial.Actor.Permissions, granted) || slices.Contains(denial.Actor.Permissions, missing) || !vmValidID(denial.RequestID) || denial.DeviceID != deviceID || denial.Mode != mode || denial.Code != "permission_denied" || denial.Reason != "permission_denied" || denial.HTTPStatus != 403 || denial.ObservedAt.IsZero() || denial.ControlOption || denial.RequestForm != (mode == "control") {
		return errors.New("mode denial lacks authenticated actor, exact permission boundary or matching console availability")
	}
	return nil
}

func verifyAssistanceModeAuthority(scenario *assistanceScenarioEvidence) error {
	a := scenario.ModeAuthority
	if a == nil || !scenario.CaptureStopped || scenario.LocalSession == nil || scenario.Media == nil {
		return errors.New("mode authority lacks a real native session and capture shutdown")
	}
	if err := verifyAssistanceActor(scenario, a.Before); err != nil {
		return err
	}
	if scenario.Name == "authority-view" {
		if scenario.Mode != "view" || a.Before.Role != assistanceViewRole || slices.Contains(a.Before.Permissions, "remote_assistance.control") || scenario.ControlGranted || scenario.Media.ControlButton || scenario.Media.RemoteApplication || scenario.EndCause != "user_stopped" {
			return errors.New("view-only native session acquired control authority")
		}
		if err := verifyAssistanceModeDenial(a.ViewDenial, scenario.DeviceID, "view", assistanceControlRole, "remote_assistance.control", "remote_assistance.view"); err != nil {
			return err
		}
		if err := verifyAssistanceModeDenial(a.ControlDenial, scenario.DeviceID, "control", assistanceViewRole, "remote_assistance.view", "remote_assistance.control"); err != nil {
			return err
		}
		if a.ControlDenial.Actor.ID != scenario.OperatorID || a.ViewDenial.Actor.ID == scenario.OperatorID {
			return errors.New("mode denials do not bind the separate real restricted actors")
		}
		return nil
	}
	if scenario.Name != "authority-control" || scenario.Mode != "control" || a.Before.Role != assistanceViewControlRole || !scenario.ControlGranted || !scenario.NonceReceived || a.After == nil || a.After.ID != scenario.OperatorID || a.After.Role != assistanceViewRole || a.After.ObservedAt.IsZero() || !slices.Contains(a.After.Permissions, "remote_assistance.view") || slices.Contains(a.After.Permissions, "remote_assistance.control") || !vmValidID(a.ChangedBy) || a.ChangedBy == scenario.OperatorID || scenario.EndCause != "authorization_lost" || scenario.EndDetail != "operator_scope_lost" {
		return errors.New("native control revocation lacks independent account change and durable authority-loss termination")
	}
	if len(a.Before.Permissions) != len(a.After.Permissions)+1 {
		return errors.New("control revocation changed other permissions")
	}
	for _, permission := range a.After.Permissions {
		if !slices.Contains(a.Before.Permissions, permission) {
			return errors.New("control revocation changed other permissions")
		}
	}
	return nil
}
