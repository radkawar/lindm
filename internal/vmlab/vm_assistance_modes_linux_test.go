//go:build linux

package vmlab

import (
	"testing"
	"time"
)

func modeAuthorityFixture(name string) *assistanceScenarioEvidence {
	const actor = "11111111-1111-4111-8111-111111111111"
	const other = "22222222-2222-4222-8222-222222222222"
	const device = "33333333-3333-4333-8333-333333333333"
	principal := func(id, role string, permissions ...string) *assistanceActor {
		return &assistanceActor{ID: id, Display: "Operator", Role: role, Permissions: permissions, ObservedAt: time.Now()}
	}
	view := principal(actor, assistanceViewRole, "remote_assistance.view", "remote_assistance.keyboard")
	scenario := &assistanceScenarioEvidence{Name: name, Mode: "view", SessionID: other, DeviceID: device, OperatorID: actor, OperatorDisplay: "Operator", EndCause: "user_stopped", CaptureStopped: true, LocalSession: &assistanceLocalEvidence{UID: 1000, LogindSessionID: "3"}, Media: &assistanceMediaEvidence{VideoWidth: 1920, VideoHeight: 1080, DecodedFrames: 20}}
	scenario.ModeAuthority = &assistanceModeAuthorityEvidence{Before: view}
	if name == "authority-control" {
		scenario.Mode = "control"
		scenario.ControlGranted, scenario.NonceReceived = true, true
		scenario.EndCause, scenario.EndDetail = "authorization_lost", "operator_scope_lost"
		scenario.ModeAuthority.Before = principal(actor, assistanceViewControlRole, "remote_assistance.view", "remote_assistance.control", "remote_assistance.keyboard")
		scenario.ModeAuthority.After = view
		scenario.ModeAuthority.ChangedBy = other
		return scenario
	}
	scenario.ModeAuthority.ViewDenial = &assistanceModeDenial{Actor: principal(other, assistanceControlRole, "remote_assistance.control"), RequestID: other, DeviceID: device, Mode: "view", Code: "permission_denied", Reason: "permission_denied", HTTPStatus: 403, ObservedAt: time.Now()}
	scenario.ModeAuthority.ControlDenial = &assistanceModeDenial{Actor: view, RequestID: actor, DeviceID: device, Mode: "control", Code: "permission_denied", Reason: "permission_denied", HTTPStatus: 403, ObservedAt: time.Now(), RequestForm: true}
	return scenario
}

func TestAssistanceViewEvidenceRequiresSeparateDeniedModes(t *testing.T) {
	if err := verifyAssistanceModeAuthority(modeAuthorityFixture("authority-view")); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*assistanceScenarioEvidence){
		"no live session":   func(s *assistanceScenarioEvidence) { s.Media = nil },
		"control granted":   func(s *assistanceScenarioEvidence) { s.ControlGranted = true },
		"input negotiated":  func(s *assistanceScenarioEvidence) { s.Media.RemoteApplication = true },
		"control offered":   func(s *assistanceScenarioEvidence) { s.ModeAuthority.ControlDenial.ControlOption = true },
		"control-only form": func(s *assistanceScenarioEvidence) { s.ModeAuthority.ViewDenial.RequestForm = true },
		"no view denial":    func(s *assistanceScenarioEvidence) { s.ModeAuthority.ViewDenial = nil },
		"wrong request":     func(s *assistanceScenarioEvidence) { s.ModeAuthority.ControlDenial.RequestID = "" },
		"no target":         func(s *assistanceScenarioEvidence) { s.ModeAuthority.ControlDenial.DeviceID = "" },
		"generic denial":    func(s *assistanceScenarioEvidence) { s.ModeAuthority.ControlDenial.Reason = "not_found" },
		"view implicitly granted": func(s *assistanceScenarioEvidence) {
			s.ModeAuthority.ViewDenial.Actor.Permissions = append(s.ModeAuthority.ViewDenial.Actor.Permissions, "remote_assistance.view")
		},
		"different view creator": func(s *assistanceScenarioEvidence) {
			s.ModeAuthority.ControlDenial.Actor.ID = s.ModeAuthority.ViewDenial.Actor.ID
		},
	} {
		t.Run(name, func(t *testing.T) {
			scenario := modeAuthorityFixture("authority-view")
			change(scenario)
			if verifyAssistanceModeAuthority(scenario) == nil {
				t.Fatal("incomplete or contradictory mode denial evidence qualified")
			}
		})
	}
}

func TestAssistanceRevocationEvidenceRequiresActualControlLoss(t *testing.T) {
	if err := verifyAssistanceModeAuthority(modeAuthorityFixture("authority-control")); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*assistanceScenarioEvidence){
		"no prior control": func(s *assistanceScenarioEvidence) {
			s.ModeAuthority.Before.Permissions = []string{"remote_assistance.view"}
		},
		"no native input": func(s *assistanceScenarioEvidence) { s.NonceReceived = false },
		"no fresh actor":  func(s *assistanceScenarioEvidence) { s.ModeAuthority.After = nil },
		"control retained": func(s *assistanceScenarioEvidence) {
			s.ModeAuthority.After.Permissions = append(s.ModeAuthority.After.Permissions, "remote_assistance.control")
		},
		"self change": func(s *assistanceScenarioEvidence) { s.ModeAuthority.ChangedBy = s.OperatorID },
		"keyboard also removed": func(s *assistanceScenarioEvidence) {
			s.ModeAuthority.After.Permissions = []string{"remote_assistance.view"}
		},
		"operator stopped": func(s *assistanceScenarioEvidence) { s.EndCause = "operator_stopped" },
		"expired instead":  func(s *assistanceScenarioEvidence) { s.EndDetail = "operator_authorization_expired" },
		"capture retained": func(s *assistanceScenarioEvidence) { s.CaptureStopped = false },
	} {
		t.Run(name, func(t *testing.T) {
			scenario := modeAuthorityFixture("authority-control")
			change(scenario)
			if verifyAssistanceModeAuthority(scenario) == nil {
				t.Fatal("unproven native control revocation qualified")
			}
		})
	}
}
