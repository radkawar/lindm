package demolab

import (
	"errors"
	"fmt"
	"slices"

	"buf.build/go/protovalidate"

	labv1 "lindm/gen/lindm/lab/v1"
	"lindm/internal/labmatrix"
	"lindm/internal/platform"
)

// Admit refuses execution unless every requested capability has both registry
// support and a latest applicable, verified PASS for the exact release and guest
// architecture. The caller loads the ledger with labmatrix.LoadLedger. Scope is
// deliberately fail-closed: arbitrary prose and golden-only records cannot
// establish TPM binding or installation.
func Admit(spec *Spec, ledger *labv1.MatrixLedger) error {
	if spec == nil || spec.Document == nil || len(spec.Devices) == 0 {
		return errors.New("demo: admission requires a loaded spec")
	}
	if ledger == nil {
		return errors.New("demo: admission requires a qualification ledger")
	}
	if err := protovalidate.Validate(ledger); err != nil {
		return fmt.Errorf("demo: validate qualification ledger: %w", err)
	}
	var refusals []error
	for _, device := range spec.Devices {
		if device.Config == nil || device.Manifest == nil || device.Release == nil {
			return errors.New("demo: admission requires resolved devices from Load")
		}
		if !(&labmatrix.Manifest{Image: device.Manifest, Release: device.Release}).Encrypted() {
			refusals = append(refusals, refusal(device, "encrypted", "manifest is not an encrypted installer"))
			continue
		}
		refusals = append(refusals, admitCapability(device, ledger, "encrypted", platform.Encryption, false))
		if device.Config.GetAssistance() {
			refusals = append(refusals, admitCapability(device, ledger, "assistance", platform.Assistance, false))
		}
		if device.Config.GetTpmBind() {
			if !device.Release.TPM2BindSupported() || slices.Contains(device.Release.Lab.TPM.Unobservable, device.Architecture) {
				refusals = append(refusals, refusal(device, "encrypted/TPM bind", "registry gates TPM2 binding on this release/architecture"))
			} else {
				refusals = append(refusals, admitCapability(device, ledger, "encrypted", platform.Encryption, true))
			}
		}
	}
	return errors.Join(refusals...)
}

func admitCapability(device Device, ledger *labv1.MatrixLedger, cell string, capability platform.Capability, tpm bool) error {
	name := cell
	if tpm {
		name += "/TPM bind"
	}
	qualified := &labv1.MatrixLedger{}
	for _, entry := range ledger.GetEntries() {
		if entry.GetPlatform() == device.Release.Key && entry.GetArchitecture() == device.Architecture && entry.GetCell() == cell && applicableScope(device, entry.GetScope(), cell, tpm) {
			qualified.Entries = append(qualified.Entries, entry)
		}
	}
	input := &labmatrix.Inputs{
		Ledger:    qualified,
		Manifests: []*labmatrix.Manifest{{Path: device.ManifestPath, Image: device.Manifest, Release: device.Release, Architecture: device.Architecture}},
	}
	cells := input.Plan([]*platform.Release{device.Release}, []*labv1.MatrixCell{{Name: cell, Capabilities: []string{string(capability)}, Image: labv1.MatrixImage_MATRIX_IMAGE_ENCRYPTED_INSTALLER, Lane: cell}})
	for _, planned := range cells {
		if planned.Architecture != device.Architecture {
			continue
		}
		if planned.State != labmatrix.Pass {
			reason := string(planned.State)
			if planned.Reason != "" {
				reason += ": " + planned.Reason
			}
			return refusal(device, name, reason)
		}
		if !planned.Entry.GetVerified() {
			return refusal(device, name, "latest applicable PASS evidence is not verified")
		}
		return nil
	}
	return refusal(device, name, "architecture is absent from registry")
}

func applicableScope(device Device, scope, cell string, tpm bool) bool {
	if scope == "" {
		return true // The ledger schema defines an empty scope as the complete lane.
	}
	firmware := device.Config.GetFirmware()
	secureBootOff := firmware != nil && firmware.SecureBoot != nil && !firmware.GetSecureBoot()
	if cell == "assistance" {
		switch scope {
		case "GNOME":
			return true
		case "GNOME, Secure Boot off":
			return secureBootOff
		case "GNOME Wayland assistance; all five scenarios; colocated dgx20; Secure Boot on",
			"GNOME Wayland assistance; all five scenarios; split controller/dgx20; Secure Boot on":
			return firmware.GetSecureBoot()
		default:
			return false
		}
	}
	switch scope {
	case "Secure Boot off":
		return secureBootOff
	case "full encryption; product TPM bind; unattended cold boot; Secure Boot enforced":
		return firmware.GetSecureBoot()
	case "TPM scenario":
		return tpm
	case "scenarios 1-4":
		return !tpm
	default:
		return false
	}
}

func refusal(device Device, cell, reason string) error {
	return fmt.Errorf("demo: refusing device %s: missing qualified cell %s/%s/%s: %s", device.Config.GetKey(), device.Release.Key, device.Architecture, cell, reason)
}
