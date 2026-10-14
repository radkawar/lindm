// SPDX-License-Identifier: Apache-2.0

//go:build linux

package vmlab

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
)

// These deliberately constructed records test only verifier rejection behavior.
// They are not native witnesses and never qualify a lab run.
func fileSafetyRegressionDisk(names []string, home bool) *assistanceFileSafetyDisk {
	disk := &assistanceFileSafetyDisk{UID: 1000, Home: "/srv/accounts/lab", Downloads: "/srv/accounts/lab/Downloads", DirectoryDevice: 8, DirectoryInode: 99, DirectoryMode: 0700, Nodes: make(map[string]*assistanceFileSafetyNode), Staging: []string{}}
	for _, name := range names {
		disk.Nodes[name] = &assistanceFileSafetyNode{assistanceFileObservation: assistanceFileObservation{Staging: []string{}}}
		if home {
			disk.Nodes["../"+name] = &assistanceFileSafetyNode{assistanceFileObservation: assistanceFileObservation{Staging: []string{}}}
		}
	}
	return disk
}

func fileSafetyRegressionDiskCopy(disk *assistanceFileSafetyDisk) *assistanceFileSafetyDisk {
	copyDisk := *disk
	copyDisk.Nodes = make(map[string]*assistanceFileSafetyNode, len(disk.Nodes))
	copyDisk.Staging = append([]string{}, disk.Staging...)
	for name, node := range disk.Nodes {
		copyNode := *node
		copyNode.Staging = append([]string{}, node.Staging...)
		copyDisk.Nodes[name] = &copyNode
	}
	return &copyDisk
}

func fileSafetyRegressionProof(t *testing.T, name string) (*assistanceScenarioEvidence, *assistanceFileSafetyProof) {
	t.Helper()
	now := time.Unix(1800000000, 0).UTC()
	scenario := &assistanceScenarioEvidence{Name: name, Mode: "control", SessionID: "11111111-1111-4111-8111-111111111111", DeviceID: "22222222-2222-4222-8222-222222222222", OperatorID: "33333333-3333-4333-8333-333333333333", OperatorDisplay: "Lab Operator", LocalSession: &assistanceLocalEvidence{UID: 1000, LogindSessionID: "7"}}
	policy := assistanceFullPolicy()
	if name == "files-limits" {
		policy.FileLimits = &agentv1.AssistanceFilePolicy{MaxFileBytes: 1024, MaxSessionBytes: 4096, AllowedMimeTypes: []string{"text/plain"}, AllowedExtensions: []string{".txt"}}
	}
	proof := &assistanceFileSafetyProof{Scenario: name, Actor: &assistanceActor{ID: scenario.OperatorID, Display: scenario.OperatorDisplay, Role: "owner", Permissions: []string{"remote_assistance.view", "remote_assistance.control", "remote_assistance.files"}, ObservedAt: now}, Session: &adminv1.AssistanceSession{Id: scenario.SessionID, DeviceId: scenario.DeviceID, OperatorId: scenario.OperatorID, State: adminv1.AssistanceState_ASSISTANCE_STATE_ACTIVE, InputState: &agentv1.AssistanceInputState{Epoch: 1}, EffectiveCapabilities: policy, GrantedCapabilities: &agentv1.AssistanceCapabilities{Policy: policy}}}
	kinds := []string{"size", "extension", "mime-source", "mime-receiver-hostile"}
	names := []string{"lindm-file-111111111111111111111111.txt", "lindm-file-222222222222222222222222.exe", "lindm-file-333333333333333333333333.txt", "lindm-file-555555555555555555555555.txt"}
	if name == "files-filesystem" {
		kinds = []string{"collision", "symlink", "path"}
		names[1], names[2] = "lindm-file-222222222222222222222222.txt", "lindm-file-444444444444444444444444.txt"
		proof.CollisionName, proof.SymlinkName, proof.ReferentName = names[0], names[1], "lindm-file-333333333333333333333333.txt"
		proof.ProtectedSource = &assistanceEvidenceFile{Name: "protected source", Path: proof.ReferentName, Bytes: 384, SHA256: strings.Repeat("b", 64)}
		protected := []string{proof.CollisionName, proof.SymlinkName, proof.ReferentName}
		proof.Fresh = fileSafetyRegressionDisk(protected, false)
		proof.Cleaned = fileSafetyRegressionDiskCopy(proof.Fresh)
		proof.Seeded = fileSafetyRegressionDiskCopy(proof.Fresh)
		for i, key := range protected {
			proof.Seeded.Nodes[key] = &assistanceFileSafetyNode{assistanceFileObservation: assistanceFileObservation{Exists: true, Regular: true, UID: 1000, Mode: 0600, Bytes: 384, SHA256: proof.ProtectedSource.SHA256, Staging: []string{}}, Device: 8, Inode: uint64(100 + i), Links: 1, ModifiedNS: now.UnixNano(), ChangedNS: now.UnixNano()}
		}
		link := proof.Seeded.Nodes[proof.SymlinkName]
		link.Regular, link.Symlink, link.Mode, link.Bytes, link.SHA256, link.LinkTarget = false, true, 0777, uint64(len(proof.ReferentName)), "", proof.ReferentName
	}
	for i, kind := range kinds {
		check := &assistanceFileSafetyCheck{Kind: kind, Name: names[i]}
		check.Before = fileSafetyRegressionDisk([]string{check.Name}, kind == "path")
		if kind == "collision" || kind == "symlink" {
			check.Before = fileSafetyRegressionDiskCopy(proof.Seeded)
		}
		check.After = fileSafetyRegressionDiskCopy(check.Before)
		request := fmt.Sprintf("%08d-4444-4444-8444-444444444444", i+1)
		audit := &assistanceAuditEvidence{ID: fmt.Sprintf("%08d-5555-4555-8555-555555555555", i+1), OccurredAt: now, ActorID: scenario.OperatorID, ResourceID: scenario.SessionID, TargetDeviceID: scenario.DeviceID, Action: "assistance.file.deny", Details: map[string]string{"request": request, "reason": "assistance_file_policy", "result": "denied"}}
		if kind == "size" || kind == "extension" || kind == "path" {
			refusal := &assistanceFileSafetyRefusal{RequestID: request, Boundary: kind, Code: "failed_precondition", Reason: "assistance_file_policy", HTTPStatus: 400, Actor: proof.Actor, Audit: audit, AuditScope: "file_authority", InputBefore: &agentv1.AssistanceInputState{Epoch: 1}, InputAfter: &agentv1.AssistanceInputState{Epoch: 1}}
			refusal.Metadata.Name, refusal.Metadata.Size, refusal.Metadata.MIME, refusal.Metadata.SHA256 = check.Name, "1", "text/plain", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
			if kind == "size" {
				refusal.Metadata.Size = "1025"
			}
			if kind == "path" {
				refusal.Metadata.Name = "../" + check.Name
				refusal.Code, refusal.Reason, refusal.Audit, refusal.AuditScope = "invalid_argument", "", nil, "schema_before_file_authority"
			}
			check.Refusal = refusal
		} else {
			reason := "file_transfer_failed"
			check.SourceMIME = "text/plain"
			if kind == "mime-source" || kind == "mime-receiver-hostile" {
				reason, check.SourceMIME = "file_type_denied", "application/pdf"
			}
			source := assistanceEvidenceFile{Name: "operator fixture", Path: check.Name, Bytes: 512, SHA256: strings.Repeat("a", 64)}
			audit.Details = map[string]string{"request": request, "reason": reason, "result": "failed", "direction": "operator_to_user", "bytes": "512", "reserved_bytes": "512", "sha256": source.SHA256, "authorized_sha256": source.SHA256, "sha256_origin": "authorized_request", "mime_type": "text/plain", "max_file_bytes": "1024", "max_session_bytes": "4096", "allowed_mime_types": "text/plain", "allowed_extensions": ".txt"}
			before, after := check.Before.Nodes[check.Name].assistanceFileObservation, check.After.Nodes[check.Name].assistanceFileObservation
			check.Attempt = &assistanceFileAttempt{Source: source, Before: &before, After: &after, Report: &agentv1.AssistanceFileReport{RequestId: request, Direction: agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER, State: agentv1.AssistanceFileState_ASSISTANCE_FILE_STATE_FAILED, BytesTransferred: 512, Reason: reason, CompletedAt: timestamppb.New(now)}, Paused: &agentv1.AssistanceInputState{Epoch: uint32(2 + 2*i), Paused: true}, Resumed: &agentv1.AssistanceInputState{Epoch: uint32(3 + 2*i)}, ConsentScreenshot: "consent-" + check.Name + ".png", ConsentOCR: "Receive a file from your support operator " + scenario.OperatorDisplay + " " + check.Name + " Downloads", Audit: audit}
			if kind == "mime-source" {
				attempt := check.Attempt
				attempt.Report.Direction = agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_FROM_USER
				attempt.Report.BytesTransferred = 0
				attempt.ConsentScreenshot, attempt.ConsentOCR = "", ""
				attempt.HostPickerTitle = "Save file"
				attempt.HostPickerScreenshot, attempt.GuestPickerScreenshot = "host-picker.png", "guest-picker.png"
				attempt.DestinationAbsent = true
				*attempt.Before = assistanceFileObservation{Exists: true, Regular: true, UID: 1000, Mode: 0400, Bytes: 512, SHA256: source.SHA256, Staging: []string{}}
				*attempt.After = *attempt.Before
				audit.Details["direction"], audit.Details["bytes"], audit.Details["reserved_bytes"] = "user_to_operator", "0", "1024"
				audit.Details["sha256"], audit.Details["authorized_sha256"], audit.Details["mime_type"] = "", "", ""
			}
			if kind == "mime-receiver-hostile" {
				fileSafetyRegressionHostile(t, scenario, proof.Actor, check)
			}
		}
		check.InputBefore = &assistanceFixtureState{Backend: "GdkWaylandDisplay", Display: "wayland-0", SessionType: "wayland", SessionID: "7", UID: 1000, PID: 123}
		for range i {
			check.InputBefore.Clicks = append(check.InputBefore.Clicks, assistancePointerWitness{Head: 0, X: 0.5, Y: 0.6})
		}
		after := *check.InputBefore
		after.Clicks = append(append([]assistancePointerWitness{}, check.InputBefore.Clicks...), assistancePointerWitness{Head: 0, X: 0.5, Y: 0.6})
		check.InputAfter = &after
		proof.Checks = append(proof.Checks, check)
	}
	// Exercise the same ordinary JSON encoding that the immutable witness uses.
	data, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	var copyProof assistanceFileSafetyProof
	if err := json.Unmarshal(data, &copyProof); err != nil {
		t.Fatal(err)
	}
	return scenario, &copyProof
}

func fileSafetyRegressionHostile(t *testing.T, scenario *assistanceScenarioEvidence, actor *assistanceActor, check *assistanceFileSafetyCheck) {
	t.Helper()
	// Actual local bytes only make canonical frame fixtures for this pure
	// verifier test. They are not transmitted and are never native evidence.
	dir := t.TempDir()
	newFixture := func(name, text string) *assistanceFileFixture {
		t.Helper()
		data := []byte(text + strings.Repeat("a", 512-len(text)))
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return &assistanceFileFixture{Name: name, Bytes: 512, SHA256: fileSafetyFrameDigest(data), Path: path}
	}
	carrier := newFixture("lindm-file-666666666666666666666666.txt", "ordinary text\n")
	payload := newFixture(check.Name, "%PDF-1.7\n")
	source := &check.Attempt.Source
	source.SHA256 = payload.SHA256
	hostile := &assistanceFileSafetyHostile{Carrier: assistanceEvidenceFile{Name: "carrier", Path: carrier.Name, Bytes: 512, SHA256: carrier.SHA256}, CarrierMIME: "text/plain"}
	check.Hostile = hostile
	request := check.Attempt.Report.GetRequestId()
	hostile.Prepared = &assistanceFileSafetyWirePrepared{RequestID: request, SessionID: scenario.SessionID, Actor: actor, Metadata: fileSafetyWireMetadata(hostile.Carrier), CarrierSHA256: carrier.SHA256, PayloadSHA256: payload.SHA256}
	outbound, inbound, err := fileSafetyWireTemplates(request, carrier, payload, hostile)
	if err != nil {
		t.Fatal(err)
	}
	observed := &assistanceFileSafetyWireObserved{RequestID: request, SessionID: scenario.SessionID, Actor: actor, CarrierSHA256: carrier.SHA256, PayloadSHA256: payload.SHA256, RPCOriginal: fileSafetyWireMetadata(hostile.Carrier), RPCForwarded: fileSafetyWireMetadata(*source), RPCForwards: 1, ChannelLabel: "lindm-files", Ordered: true, Reliable: true, Restored: true}
	for i, frame := range hostile.ExpectedOutbound {
		frame.Original, frame.Forwarded = outbound[i].Original, outbound[i].Forwarded
		observed.Outbound = append(observed.Outbound, frame)
	}
	for i, frame := range hostile.ExpectedInbound {
		frame.Data = inbound[i].Data
		observed.Inbound = append(observed.Inbound, frame)
	}
	hostile.Observed = observed
	check.Before = fileSafetyRegressionDisk([]string{check.Name, carrier.Name}, false)
	check.After = fileSafetyRegressionDiskCopy(check.Before)
	check.Attempt.Audit.Details["sha256"], check.Attempt.Audit.Details["authorized_sha256"] = payload.SHA256, payload.SHA256
	check.Attempt.Audit.Details["max_session_bytes"] = "3072"
}

func TestFileSafetyVerifierRequiresCompleteAuthorityAndObservations(t *testing.T) {
	for _, name := range []string{"files-filesystem", "files-limits"} {
		t.Run(name, func(t *testing.T) {
			scenario, proof := fileSafetyRegressionProof(t, name)
			if err := verifyFileSafety(scenario, proof); err != nil {
				t.Fatalf("constructed verifier fixture rejected: %v", err)
			}
			for label, mutate := range map[string]func(*assistanceFileSafetyProof){
				"missing checks": func(p *assistanceFileSafetyProof) { p.Checks = nil },
				"nil check":      func(p *assistanceFileSafetyProof) { p.Checks[0] = nil },
				"wrong scenario": func(p *assistanceFileSafetyProof) { p.Scenario = "files-copy" },
				"missing actor":  func(p *assistanceFileSafetyProof) { p.Actor = nil },
				"wrong actor":    func(p *assistanceFileSafetyProof) { p.Actor.ID = scenario.DeviceID },
				"missing permission": func(p *assistanceFileSafetyProof) {
					p.Actor.Permissions = []string{"remote_assistance.view", "remote_assistance.control"}
				},
				"missing session": func(p *assistanceFileSafetyProof) { p.Session = nil },
				"ended session":   func(p *assistanceFileSafetyProof) { p.Session.State = adminv1.AssistanceState_ASSISTANCE_STATE_ENDED },
				"other device":    func(p *assistanceFileSafetyProof) { p.Session.DeviceId = scenario.OperatorID },
				"files off": func(p *assistanceFileSafetyProof) {
					p.Session.GrantedCapabilities.Policy.Files = agentv1.AssistancePolicyMode_ASSISTANCE_POLICY_MODE_OFF
				},
				"paused baseline":        func(p *assistanceFileSafetyProof) { p.Session.InputState.Paused = true },
				"missing disk":           func(p *assistanceFileSafetyProof) { p.Checks[0].After = nil },
				"missing node":           func(p *assistanceFileSafetyProof) { delete(p.Checks[0].After.Nodes, p.Checks[0].Name) },
				"unobserved staging":     func(p *assistanceFileSafetyProof) { p.Checks[0].After.Staging = nil },
				"left staging":           func(p *assistanceFileSafetyProof) { p.Checks[0].After.Staging = []string{".lindm-transfer-private"} },
				"changed downloads":      func(p *assistanceFileSafetyProof) { p.Checks[0].After.DirectoryInode++ },
				"root observer":          func(p *assistanceFileSafetyProof) { p.Checks[0].After.UID = 0 },
				"wrong downloads":        func(p *assistanceFileSafetyProof) { p.Checks[0].After.Downloads = "/tmp/Downloads" },
				"stale input":            func(p *assistanceFileSafetyProof) { p.Checks[0].InputAfter = p.Checks[0].InputBefore },
				"wrong input process":    func(p *assistanceFileSafetyProof) { p.Checks[0].InputAfter.PID++ },
				"wrong input user":       func(p *assistanceFileSafetyProof) { p.Checks[0].InputAfter.UID++ },
				"wrong input coordinate": func(p *assistanceFileSafetyProof) { p.Checks[0].InputAfter.Clicks[0].X = 0.1 },
				"recycled input across checks": func(p *assistanceFileSafetyProof) {
					p.Checks[1].InputBefore = p.Checks[0].InputBefore
					p.Checks[1].InputAfter = p.Checks[0].InputAfter
				},
				"changed account across checks": func(p *assistanceFileSafetyProof) {
					for _, d := range []*assistanceFileSafetyDisk{p.Checks[2].Before, p.Checks[2].After} {
						d.Home, d.Downloads = "/srv/other", "/srv/other/Downloads"
					}
				},
			} {
				t.Run(label, func(t *testing.T) {
					scenario, proof := fileSafetyRegressionProof(t, name)
					mutate(proof)
					if err := verifyFileSafety(scenario, proof); err == nil {
						t.Fatal("incomplete safety evidence accepted")
					}
				})
			}
		})
	}
}

func TestFileSafetyFilesystemRejectsChangedTargetsAndFakeRefusals(t *testing.T) {
	for label, mutate := range map[string]func(*assistanceFileSafetyProof){
		"missing protected bytes":  func(p *assistanceFileSafetyProof) { p.ProtectedSource = nil },
		"missing cleanup":          func(p *assistanceFileSafetyProof) { p.Cleaned = nil },
		"seeded another directory": func(p *assistanceFileSafetyProof) { p.Seeded.DirectoryInode++ },
		"missing fresh baseline":   func(p *assistanceFileSafetyProof) { p.Fresh = nil },
		"nonfresh fixture":         func(p *assistanceFileSafetyProof) { p.Fresh = p.Seeded },
		"collision overwrite": func(p *assistanceFileSafetyProof) {
			p.Checks[0].After.Nodes[p.CollisionName].SHA256 = strings.Repeat("a", 64)
		},
		"collision inode replacement": func(p *assistanceFileSafetyProof) { p.Checks[0].After.Nodes[p.CollisionName].Inode++ },
		"same bytes rewritten":        func(p *assistanceFileSafetyProof) { p.Checks[0].After.Nodes[p.CollisionName].ChangedNS++ },
		"symlink replaced":            func(p *assistanceFileSafetyProof) { p.Checks[1].After.Nodes[p.SymlinkName].Inode++ },
		"symlink redirected": func(p *assistanceFileSafetyProof) {
			p.Checks[1].After.Nodes[p.SymlinkName].LinkTarget = p.CollisionName
		},
		"referent changed": func(p *assistanceFileSafetyProof) {
			p.Checks[1].After.Nodes[p.ReferentName].SHA256 = strings.Repeat("a", 64)
		},
		"missing referent": func(p *assistanceFileSafetyProof) { delete(p.Checks[1].After.Nodes, p.ReferentName) },
		"missing approval": func(p *assistanceFileSafetyProof) { p.Checks[0].Attempt.ConsentScreenshot = "" },
		"wrong approval name": func(p *assistanceFileSafetyProof) {
			p.Checks[0].Attempt.ConsentOCR = "Receive a file from your support operator Lab Operator other.txt Downloads"
		},
		"decline instead of collision": func(p *assistanceFileSafetyProof) { p.Checks[0].Attempt.Report.Reason = "file_declined" },
		"early unrelated failure":      func(p *assistanceFileSafetyProof) { p.Checks[0].Attempt.Report.BytesTransferred = 0 },
		"verified publication": func(p *assistanceFileSafetyProof) {
			p.Checks[0].Attempt.Report.File = &agentv1.AssistanceFileMetadata{}
		},
		"missing transfer audit": func(p *assistanceFileSafetyProof) { p.Checks[0].Attempt.Audit = nil },
		"wrong audit actor":      func(p *assistanceFileSafetyProof) { p.Checks[0].Attempt.Audit.ActorID = "other" },
		"unverified audit digest": func(p *assistanceFileSafetyProof) {
			p.Checks[0].Attempt.Audit.Details["sha256_origin"] = "receiver_verified"
		},
		"wrong transfer audit reason": func(p *assistanceFileSafetyProof) { p.Checks[0].Attempt.Audit.Details["reason"] = "file_cancelled" },
		"stale resumed epoch": func(p *assistanceFileSafetyProof) {
			p.Checks[0].Attempt.Resumed.Epoch = p.Checks[0].Attempt.Paused.Epoch
		},
		"no lexical traversal":                  func(p *assistanceFileSafetyProof) { p.Checks[2].Refusal.Metadata.Name = p.Checks[2].Name },
		"path outside unobserved":               func(p *assistanceFileSafetyProof) { delete(p.Checks[2].After.Nodes, "../"+p.Checks[2].Name) },
		"invented traversal authority":          func(p *assistanceFileSafetyProof) { p.Checks[2].Refusal.AuditScope = "file_authority" },
		"invented traversal domain audit":       func(p *assistanceFileSafetyProof) { p.Checks[2].Refusal.Audit = p.Checks[0].Attempt.Audit },
		"handler reason instead of interceptor": func(p *assistanceFileSafetyProof) { p.Checks[2].Refusal.Reason = "invalid_assistance_file" },
	} {
		t.Run(label, func(t *testing.T) {
			scenario, proof := fileSafetyRegressionProof(t, "files-filesystem")
			mutate(proof)
			if err := verifyFileSafety(scenario, proof); err == nil {
				t.Fatal("unproven filesystem boundary accepted")
			}
		})
	}
}

func TestFileSafetyLimitsRequiresSpecificPolicyAndNativeSourceMIME(t *testing.T) {
	for label, mutate := range map[string]func(*assistanceFileSafetyProof){
		"wrong ceiling": func(p *assistanceFileSafetyProof) { p.Session.EffectiveCapabilities.FileLimits.MaxFileBytes++ },
		"wrong quota":   func(p *assistanceFileSafetyProof) { p.Session.GrantedCapabilities.Policy.FileLimits.MaxSessionBytes++ },
		"PDF actually allowed": func(p *assistanceFileSafetyProof) {
			p.Session.GrantedCapabilities.Policy.FileLimits.AllowedMimeTypes = append(p.Session.GrantedCapabilities.Policy.FileLimits.AllowedMimeTypes, "application/pdf")
		},
		"size within limit":       func(p *assistanceFileSafetyProof) { p.Checks[0].Refusal.Metadata.Size = "1024" },
		"generic RPC failure":     func(p *assistanceFileSafetyProof) { p.Checks[0].Refusal.Code = "internal" },
		"unrelated policy reason": func(p *assistanceFileSafetyProof) { p.Checks[0].Refusal.Reason = "assistance_command_busy" },
		"wrong HTTP status":       func(p *assistanceFileSafetyProof) { p.Checks[0].Refusal.HTTPStatus = 403 },
		"admission audit omitted": func(p *assistanceFileSafetyProof) { p.Checks[0].Refusal.Audit = nil },
		"missing RPC actor":       func(p *assistanceFileSafetyProof) { p.Checks[0].Refusal.Actor = nil },
		"wrong typed audit":       func(p *assistanceFileSafetyProof) { p.Checks[1].Refusal.Audit.Details["reason"] = "not_creator" },
		"audit text fallback": func(p *assistanceFileSafetyProof) {
			a := p.Checks[0].Refusal.Audit
			a.Reason = "reason=assistance_file_policy result=denied"
			a.Details = nil
		},
		"extension not requested":           func(p *assistanceFileSafetyProof) { p.Checks[1].Refusal.Metadata.Name = "other.txt" },
		"extension denied by MIME instead":  func(p *assistanceFileSafetyProof) { p.Checks[1].Refusal.Metadata.MIME = "application/pdf" },
		"native source never contained PDF": func(p *assistanceFileSafetyProof) { p.Checks[2].SourceMIME = "text/plain" },
		"generic native source failure":     func(p *assistanceFileSafetyProof) { p.Checks[2].Attempt.Report.Reason = "file_transfer_failed" },
		"native source unbound":             func(p *assistanceFileSafetyProof) { p.Checks[2].Attempt.Source.SHA256 = "" },
		"native source policy missing":      func(p *assistanceFileSafetyProof) { delete(p.Checks[2].Attempt.Audit.Details, "allowed_mime_types") },
		"receiver direction falsely claimed": func(p *assistanceFileSafetyProof) {
			p.Checks[2].Attempt.Report.Direction = agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_TO_USER
		},
		"missing real guest picker": func(p *assistanceFileSafetyProof) { p.Checks[2].Attempt.GuestPickerScreenshot = "" },
		"missing real host picker":  func(p *assistanceFileSafetyProof) { p.Checks[2].Attempt.HostPickerScreenshot = "" },
		"source bytes disclosed":    func(p *assistanceFileSafetyProof) { p.Checks[2].Attempt.Report.BytesTransferred = 512 },
		"missing guest source":      func(p *assistanceFileSafetyProof) { p.Checks[2].Attempt.Before.Exists = false },
		"wrong guest source hash":   func(p *assistanceFileSafetyProof) { p.Checks[2].Attempt.Before.SHA256 = strings.Repeat("f", 64) },
		"destination unobserved":    func(p *assistanceFileSafetyProof) { p.Checks[2].Attempt.DestinationAbsent = false },
		"false receiver digest audit": func(p *assistanceFileSafetyProof) {
			p.Checks[2].Attempt.Audit.Details["sha256_origin"] = "receiver_verified"
		},
		"unexpected output":         func(p *assistanceFileSafetyProof) { p.Checks[2].After.Nodes[p.Checks[2].Name].Exists = true },
		"missing epoch observation": func(p *assistanceFileSafetyProof) { p.Checks[0].Refusal.InputAfter = nil },
	} {
		t.Run(label, func(t *testing.T) {
			scenario, proof := fileSafetyRegressionProof(t, "files-limits")
			mutate(proof)
			if err := verifyFileSafety(scenario, proof); err == nil {
				t.Fatal("unproven file limits boundary accepted")
			}
		})
	}
}

func TestFileSafetyVerifierRejectsMissingProof(t *testing.T) {
	scenario, proof := fileSafetyRegressionProof(t, "files-limits")
	if err := verifyFileSafety(scenario, nil); err == nil {
		t.Fatal("missing safety proof accepted")
	}
	if err := verifyFileSafety(nil, proof); err == nil {
		t.Fatal("missing safety scenario accepted")
	}
}

func TestFileSafetyProofExportsBoundArtifacts(t *testing.T) {
	for _, name := range []string{"files-filesystem", "files-limits"} {
		_, proof := fileSafetyRegressionProof(t, name)
		wantArtifacts, wantShots := 3, 2
		if name == "files-limits" {
			wantArtifacts, wantShots = 3, 3
		}
		if len(proof.fileArtifacts()) != wantArtifacts || len(proof.screenshotPaths()) != wantShots {
			t.Fatalf("%s omitted nested evidence bindings", name)
		}
	}
}

func TestFileSafetySourceMIMEAllowsOnlyIndependentlyEmptyPlaceholder(t *testing.T) {
	scenario, proof := fileSafetyRegressionProof(t, "files-limits")
	check := proof.Checks[2]
	check.Attempt.DestinationAbsent = false
	check.Attempt.Destination = &assistanceEvidenceFile{Path: "saved-" + check.Name, Bytes: 0, SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
	if err := verifyFileSafety(scenario, proof); err != nil {
		t.Fatal(err)
	}
	if len(proof.fileArtifacts()) != 4 {
		t.Fatal("empty destination artifact omitted from proof binding")
	}
	check.Attempt.Destination.SHA256 = strings.Repeat("a", 64)
	if err := verifyFileSafety(scenario, proof); err == nil {
		t.Fatal("claimed empty destination without empty-file hash accepted")
	}
}

func TestFileSafetyReceiverRequiresActualHostileInputAndNativeDenial(t *testing.T) {
	for label, mutate := range map[string]func(*assistanceFileSafetyCheck){
		"normal UI falsely claimed": func(c *assistanceFileSafetyCheck) { c.Hostile = nil },
		"carrier missing":           func(c *assistanceFileSafetyCheck) { c.Hostile.Carrier.SHA256 = "" },
		"same carrier and payload":  func(c *assistanceFileSafetyCheck) { c.Hostile.Carrier.Path = c.Name },
		"original RPC not observed": func(c *assistanceFileSafetyCheck) { c.Hostile.Prepared = nil },
		"wire not observed":         func(c *assistanceFileSafetyCheck) { c.Hostile.Observed = nil },
		"wrong authenticated actor": func(c *assistanceFileSafetyCheck) { c.Hostile.Observed.Actor.ID = "other" },
		"wrong operation": func(c *assistanceFileSafetyCheck) {
			c.Hostile.Observed.RequestID = "77777777-7777-4777-8777-777777777777"
		},
		"wrong RPC destination":         func(c *assistanceFileSafetyCheck) { c.Hostile.Observed.RPCForwarded.Name = c.Hostile.Carrier.Path },
		"RPC declares PDF":              func(c *assistanceFileSafetyCheck) { c.Hostile.Observed.RPCForwarded.MIME = "application/pdf" },
		"extra RPC forwarding":          func(c *assistanceFileSafetyCheck) { c.Hostile.Observed.RPCForwards = 2 },
		"wrong channel":                 func(c *assistanceFileSafetyCheck) { c.Hostile.Observed.ChannelLabel = "lindm-input" },
		"unordered channel":             func(c *assistanceFileSafetyCheck) { c.Hostile.Observed.Ordered = false },
		"unreliable channel":            func(c *assistanceFileSafetyCheck) { c.Hostile.Observed.Reliable = false },
		"wrapper not restored":          func(c *assistanceFileSafetyCheck) { c.Hostile.Observed.Restored = false },
		"missing Start frame":           func(c *assistanceFileSafetyCheck) { c.Hostile.Observed.Outbound = c.Hostile.Observed.Outbound[1:] },
		"missing real Ready":            func(c *assistanceFileSafetyCheck) { c.Hostile.Observed.Inbound = c.Hostile.Observed.Inbound[1:] },
		"missing real End":              func(c *assistanceFileSafetyCheck) { c.Hostile.Observed.Outbound[2].Forwarded = nil },
		"corrupt actual wire bytes":     func(c *assistanceFileSafetyCheck) { c.Hostile.Observed.Outbound[1].Forwarded[20] ^= 1 },
		"expected digest merely echoed": func(c *assistanceFileSafetyCheck) { c.Hostile.Observed.Outbound[1].Forwarded = nil },
		"wrong wire request hash": func(c *assistanceFileSafetyCheck) {
			c.Hostile.Observed.Outbound[0].ForwardedSHA256 = strings.Repeat("f", 64)
		},
		"receiver never got full payload": func(c *assistanceFileSafetyCheck) { c.Attempt.Report.BytesTransferred = 0 },
		"generic transfer failure":        func(c *assistanceFileSafetyCheck) { c.Attempt.Report.Reason = "file_transfer_failed" },
		"source direction substituted": func(c *assistanceFileSafetyCheck) {
			c.Attempt.Report.Direction = agentv1.AssistanceFileDirection_ASSISTANCE_FILE_DIRECTION_FROM_USER
		},
		"payload published":       func(c *assistanceFileSafetyCheck) { c.After.Nodes[c.Name].Exists = true },
		"carrier path unobserved": func(c *assistanceFileSafetyCheck) { delete(c.After.Nodes, c.Hostile.Carrier.Path) },
		"wrong remaining quota":   func(c *assistanceFileSafetyCheck) { c.Attempt.Audit.Details["max_session_bytes"] = "4096" },
	} {
		t.Run(label, func(t *testing.T) {
			scenario, proof := fileSafetyRegressionProof(t, "files-limits")
			mutate(proof.Checks[3])
			if err := verifyFileSafety(scenario, proof); err == nil {
				t.Fatal("unproven hostile sender or incoming receiver MIME denial accepted")
			}
		})
	}
}

func TestFileSafetyHostileVerifierChecksBytesNotOnlyClaimedFrameDigests(t *testing.T) {
	scenario, proof := fileSafetyRegressionProof(t, "files-limits")
	h := proof.Checks[3].Hostile
	// Even internally consistent telemetry cannot claim text wire bytes were PDF.
	frame := &h.Observed.Outbound[1]
	frame.Forwarded = append([]byte{}, frame.Original...)
	frame.ForwardedSHA256 = fileSafetyFrameDigest(frame.Forwarded)
	frame.ForwardedBytes = len(frame.Forwarded)
	h.ExpectedOutbound[1].ForwardedSHA256 = frame.ForwardedSHA256
	h.ExpectedOutbound[1].ForwardedBytes = frame.ForwardedBytes
	if err := verifyFileSafety(scenario, proof); err == nil {
		t.Fatal("matching telemetry digests hid a non-PDF transmitted payload")
	}
	scenario, proof = fileSafetyRegressionProof(t, "files-limits")
	h = proof.Checks[3].Hostile
	// A second real Ready is not a receiver MIME-denial Cancel.
	cancel := &h.Observed.Inbound[1]
	cancel.Data = append([]byte{}, h.Observed.Inbound[0].Data...)
	cancel.SHA256, cancel.Bytes = fileSafetyFrameDigest(cancel.Data), len(cancel.Data)
	h.ExpectedInbound[1].SHA256, h.ExpectedInbound[1].Bytes = cancel.SHA256, cancel.Bytes
	if err := verifyFileSafety(scenario, proof); err == nil {
		t.Fatal("matching telemetry digests hid a missing receiver MIME denial")
	}
}
