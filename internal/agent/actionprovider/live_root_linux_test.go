//go:build linux

package actionprovider

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"lindm/internal/agent/nativeexec"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "lindm/gen/lindm/agent/v1"
)

func liveScopeFixture() (*Provider, *agentv1.DeviceActionSpec) {
	root := &agentv1.StorageTarget{IdentityBasis: agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_WWN_SERIAL, LuksUuid: fixtureLUKS, Wwn: "root-wwn", Serial: "root-serial", SizeBytes: 64 << 20}
	data := &agentv1.StorageTarget{IdentityBasis: agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_WWN_SERIAL, LuksUuid: "ea5f1f9c-fd35-476d-996b-f771484ec8e2", Wwn: "data-wwn", Serial: "data-serial", SizeBytes: 64 << 20}
	p := &Provider{config: &agentv1.DeviceActionProviderConfig{AllowLiveRootCryptoErase: true, Targets: []*agentv1.QualifiedActionTarget{{Target: root, AllowCryptoErase: true, QualificationId: "root-test"}, {Target: data, AllowCryptoErase: true, QualificationId: "data-test"}}}}
	spec := &agentv1.DeviceActionSpec{Action: &agentv1.DeviceActionSpec_CryptoErase{CryptoErase: &agentv1.CryptoEraseAction{Mode: agentv1.CryptoEraseMode_CRYPTO_ERASE_MODE_LIVE_ROOT_HEADER, Targets: []*agentv1.StorageTarget{proto.CloneOf(root), proto.CloneOf(data)}}}}
	return p, spec
}

func TestLiveRootRequiresCompleteQualifiedEncryptedSet(t *testing.T) {
	for _, variant := range []string{"exact", "missing-root", "missing-data", "extra", "duplicate", "changed-size", "unqualified-data", "disabled", "single-offline-target"} {
		t.Run(variant, func(t *testing.T) {
			p, spec := liveScopeFixture()
			action := spec.GetCryptoErase()
			switch variant {
			case "missing-root":
				action.Targets = action.Targets[1:]
			case "missing-data":
				action.Targets = action.Targets[:1]
			case "extra":
				action.Targets = append(action.Targets, &agentv1.StorageTarget{IdentityBasis: agentv1.StorageIdentityBasis_STORAGE_IDENTITY_BASIS_WWN_SERIAL, LuksUuid: "83357b28-c8d0-4185-a614-64415dc9eaf0", Wwn: "extra", Serial: "extra", SizeBytes: 64 << 20})
			case "duplicate":
				action.Targets[1] = proto.CloneOf(action.Targets[0])
			case "changed-size":
				action.Targets[1].SizeBytes++
			case "unqualified-data":
				p.config.Targets[1].AllowCryptoErase = false
			case "disabled":
				p.config.AllowLiveRootCryptoErase = false
			case "single-offline-target":
				action.Target = action.Targets[0]
			}
			if err := p.liveRootScope(spec); (err == nil) != (variant == "exact") {
				t.Fatalf("scope %s: %v", variant, err)
			}
		})
	}
}

func TestRootBackingRequiresActualSingleLUKS2Dependency(t *testing.T) {
	p, _ := liveScopeFixture()
	targets := []*targetHandle{{qualification: p.config.Targets[0], node: blockNode{Device: "8:2"}}, {qualification: p.config.Targets[1], node: blockNode{Device: "8:16"}}}
	id := "CRYPT-LUKS2-" + strings.ReplaceAll(fixtureLUKS, "-", "") + "-root"
	index, err := matchRootBacking(targets, map[string]bool{"253:0": true, "8:2": true}, []string{id})
	if err != nil || index != 0 {
		t.Fatalf("actual root: %d %v", index, err)
	}
	for _, crypt := range [][]string{nil, {"CRYPT-LUKS2-wrong-root"}, {id, id}, {"CRYPT-PLAIN-root"}} {
		if _, err := matchRootBacking(targets, map[string]bool{"8:2": true}, crypt); err == nil {
			t.Fatal("unqualified mapping accepted")
		}
	}
	if _, err := matchRootBacking(targets, map[string]bool{"8:1": true}, []string{id}); err == nil {
		t.Fatal("same physical disk mistaken for actual root backing")
	}
}

func TestLiveRootEffectOrdersGatePoweroffAllHeadersAndSurvivesNetworkLoss(t *testing.T) {
	for _, variant := range []string{"success", "gate-denied", "poweroff-arm-failed", "first-native-failed", "network-lost", "raw-readback-failed"} {
		t.Run(variant, func(t *testing.T) {
			p, spec := liveScopeFixture()
			p.clock = func() time.Time { return time.Unix(1800000000, 0) }
			plan := &agentv1.DeviceActionPlan{Spec: spec, Before: &agentv1.DeviceActionObservation{ObservedAt: timestamppb.New(p.clock()), Supported: true, Encrypted: true}}
			var handles []*targetHandle
			for _, qualified := range p.config.Targets {
				file, err := os.CreateTemp(t.TempDir(), "header-not-a-device-")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = file.Close() })
				if _, err := file.Write(bytes.Repeat([]byte{0xaa}, 128<<10)); err != nil {
					t.Fatal(err)
				}
				handles = append(handles, &targetHandle{file: file, qualification: qualified})
				plan.CryptoEraseTargets = append(plan.CryptoEraseTargets, &agentv1.CryptoEraseTargetPlan{Target: qualified.GetTarget(), LuksHeaderBytes: 64 << 10})
			}
			// The native runner reports exits as *nativeexec.ExitError.
			exit := &nativeexec.ExitError{Program: "cryptsetup", Code: 1}
			consumed, armed, erases := false, false, 0
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			p.flushHeader = func(file *os.File) error {
				if variant == "raw-readback-failed" {
					_, err := file.WriteAt([]byte{1}, 8192)
					return err
				}
				return nil
			}
			p.run = func(work context.Context, request nativeRequest) ([]byte, error) {
				if !consumed {
					t.Fatal("native effect before durable gate")
				}
				if request.command == systemctl {
					if len(request.args) != 2 || request.args[0] != "start" || request.args[1] != LiveRootPoweroffService {
						t.Fatal("non-fixed poweroff authority")
					}
					if variant == "poweroff-arm-failed" {
						return nil, errors.New("PID1 did not acknowledge readiness")
					}
					armed = true
					if variant == "network-lost" {
						cancel()
					}
					return nil, nil
				}
				if !armed || request.command != cryptsetup {
					t.Fatal("header effect preceded independent forced-poweroff timer")
				}
				if work.Err() != nil {
					t.Fatal("report/network cancellation reached consumed effect")
				}
				switch request.args[0] {
				case "luksErase":
					erases++
					if variant == "first-native-failed" && erases == 1 {
						return nil, errors.New("partial native failure")
					}
					return nil, nil
				case "luksDump":
					return nil, errors.Join(errNativeNotLUKS, exit)
				default:
					t.Fatal("unexpected native command")
					return nil, ErrUnsupported
				}
			}
			result, err := p.executeLiveRoot(ctx, plan, handles, make([]byte, 2<<20), func(context.Context) error {
				if variant == "gate-denied" {
					return ErrConflict
				}
				consumed = true
				return nil
			})
			wantSuccess := variant == "success" || variant == "network-lost"
			if (err == nil) != wantSuccess || result.GetVerified() != wantSuccess {
				t.Fatalf("result variant=%s verified=%v err=%v", variant, result.GetVerified(), err)
			}
			wantErases := 2
			if variant == "gate-denied" || variant == "poweroff-arm-failed" {
				wantErases = 0
			}
			if erases != wantErases {
				t.Fatalf("omitted or premature effect: %d want %d", erases, wantErases)
			}
			for _, target := range handles {
				var data [1]byte
				if _, err := target.file.ReadAt(data[:], 64<<10); err != nil || data[0] != 0xaa {
					t.Fatal("live path overwrote data instead of headers only")
				}
				if wantErases == 0 {
					if _, err := target.file.ReadAt(data[:], 0); err != nil || data[0] != 0xaa {
						t.Fatal("rejected action modified a header")
					}
				}
			}
		})
	}
}
