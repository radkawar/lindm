//go:build linux

package vmlab

import (
	"context"
	"errors"
	"strings"
	"time"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

// VMRecoveryReadinessEvidence binds the first published host observation's root
// projection to the installed executor's own journal and the guest's LSM denial
// records. Storage must come from a successful root observation; an executor
// readiness transport failure is a lane failure, not a tolerated platform gap.
type VMRecoveryReadinessEvidence struct {
	HostSequence         uint64   `json:"host_sequence"`
	StorageStatus        string   `json:"storage_status"`
	StorageDevices       int      `json:"storage_devices"`
	ReadinessAvailable   bool     `json:"readiness_available"`
	ReadinessReason      string   `json:"readiness_reason,omitempty"`
	CPUModelSource       string   `json:"cpu_model_source,omitempty"`
	HardwareSerialStatus string   `json:"hardware_serial_status"`
	FirmwareModeStatus   string   `json:"firmware_mode_status"`
	ExecutorJournal      []string `json:"executor_readiness_journal,omitempty"`
	InventoryUnits       []string `json:"inventory_unit_journal,omitempty"`
	Denials              []string `json:"lsm_denials,omitempty"`
}

// The guest diagnostics are bounded, line-filtered nonsecret records: executor
// readiness failures, transient inventory unit state and LSM denials.
const vmReadinessGuestJournal = `sudo -n sh -c '` +
	`journalctl -b --no-pager -o short-iso -u lindm-executor.service | grep -F "recovery readiness" | tail -n 20; echo ==; ` +
	`journalctl -b --no-pager -o short-iso | grep -F lindm-inventory- | tail -n 40; echo ==; ` +
	`journalctl -b --no-pager -o short-iso _TRANSPORT=audit + _TRANSPORT=kernel | grep -E "avc: +denied|SELINUX_ERR|apparmor=.DENIED" | tail -n 40; ` +
	`true'`

func waitVMRecoveryReadiness(ctx context.Context, vm *guestVM, control *vmControlPlane, deviceID string) (*VMRecoveryReadinessEvidence, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	evidence := new(VMRecoveryReadinessEvidence)
	for {
		detail, err := control.GetDevice(ctx, deviceID)
		if err != nil {
			return nil, err
		}
		host := detail.GetHost()
		details := host.GetObservation().GetDetails()
		if readiness := details.GetRecoveryReadiness(); readiness != nil {
			evidence.HostSequence = host.GetSequence()
			evidence.StorageStatus = details.GetStorage().GetStatus().String()
			evidence.StorageDevices = len(details.GetStorage().GetDevices())
			evidence.ReadinessAvailable, evidence.ReadinessReason = readiness.GetAvailable(), readiness.GetReason()
			evidence.CPUModelSource = details.GetCpu().GetModelSource().GetValue()
			evidence.HardwareSerialStatus = host.GetObservation().GetHardwareSerial().GetStatus().String()
			evidence.FirmwareModeStatus = details.GetFirmware().GetMode().GetStatus().String()
			break
		}
		select {
		case <-ctx.Done():
			return nil, errors.New("published host observation did not carry recovery readiness")
		case <-ticker.C:
		}
	}
	output, err := vm.runResult(ctx, vmReadinessGuestJournal, nil, 256<<10, 30*time.Second)
	if err != nil {
		return evidence, err
	}
	sections := strings.SplitN(string(output.Stdout), "==\n", 3)
	for i, target := range []*[]string{&evidence.ExecutorJournal, &evidence.InventoryUnits, &evidence.Denials} {
		if i < len(sections) {
			*target = strings.FieldsFunc(sections[i], func(r rune) bool { return r == '\n' })
		}
	}
	if evidence.StorageStatus != inventoryv1.CollectionStatus_COLLECTION_STATUS_SUCCESS.String() ||
		strings.HasPrefix(evidence.ReadinessReason, "recovery_readiness_executor_") {
		return evidence, errors.New("published host observation lacks the executor's root storage observation: " + evidence.ReadinessReason)
	}
	return evidence, nil
}
