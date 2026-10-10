//go:build linux

package vmlab

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/reflect/protoreflect"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

// CheckInventoryHealth rejects collection failures, including failures that match
// an independent oracle. Only the checked-in distro/field/capability exceptions
// in inventory_unavailable_linux.go permit UNAVAILABLE. It checks fresh evidence,
// not historical projections; missing current inventory categories are failures.
// This is a health gate, not a substitute for independent native value comparison.
func CheckInventoryHealth(host *inventoryv1.HostObservation, packages *inventoryv1.PackageObservation) error {
	if host == nil || host.GetOsId().GetStatus() != truthSuccess || host.GetOsId().GetValue() == "" {
		return errors.New("inventory health requires a successful OS identity")
	}
	context := inventoryHealthContext{distro: host.OsId.Value, host: host, details: host.Details}
	if err := checkInventoryMessage(host.ProtoReflect(), "host", context, true); err != nil {
		return err
	}
	return CheckInventoryPackageHealth(context.distro, packages)
}

// CheckInventoryPackageHealth checks the package collection and every package's
// native module status. Non-RPM module absence is allowed only for the distro's
// native package manager; package collection itself must always succeed.
func CheckInventoryPackageHealth(distro string, packages *inventoryv1.PackageObservation) error {
	if packages == nil {
		return errors.New("inventory health missing packages")
	}
	return checkInventoryMessage(packages.ProtoReflect(), "packages", inventoryHealthContext{distro: distro}, true)
}

type inventoryHealthContext struct {
	distro  string
	host    *inventoryv1.HostObservation
	details *inventoryv1.NativeDetails
	block   *inventoryv1.BlockDevice
	session *inventoryv1.ActiveSession
	pkg     *inventoryv1.Package
}

func checkInventoryMessage(message protoreflect.Message, path string, context inventoryHealthContext, requireFields bool) error {
	if !message.IsValid() {
		return fmt.Errorf("inventory health missing %s", path)
	}
	switch value := message.Interface().(type) {
	case *inventoryv1.CpuDetails:
		if value.ModelSource == nil || value.Model == nil || value.ModelSource.Status != value.Model.Status {
			return fmt.Errorf("inventory health missing or inconsistent %s.model_source", path)
		}
		if value.ModelSource.Status == truthSuccess {
			switch value.ModelSource.Value {
			case "proc_cpuinfo", "smbios_type4", "arm_midr_procfs", "arm_midr_sysfs":
			default:
				return fmt.Errorf("inventory health invalid %s.model_source", path)
			}
		}
	case *inventoryv1.BlockDevice:
		context.block = value
	case *inventoryv1.ActiveSession:
		context.session = value
	case *inventoryv1.Package:
		context.pkg = value
	case *inventoryv1.RepositoryObservation:
		if value.Status == truthSuccess {
			if len(value.Ids) != len(value.Configurations) {
				return fmt.Errorf("inventory health incomplete %s.configurations", path)
			}
			ids := make(map[string]bool, len(value.Ids))
			for _, id := range value.Ids {
				if id == "" || ids[id] {
					return fmt.Errorf("inventory health invalid %s.ids", path)
				}
				ids[id] = true
			}
			for _, configuration := range value.Configurations {
				if configuration == nil || !ids[configuration.Id] {
					return fmt.Errorf("inventory health invalid %s.configurations", path)
				}
				delete(ids, configuration.Id)
			}
		}
	}
	fields := message.Descriptor().Fields()
	for i := range fields.Len() {
		field := fields.Get(i)
		name := path + "." + string(field.Name())
		if field.Kind() == protoreflect.EnumKind && field.Enum().FullName() == "lindm.inventory.v1.CollectionStatus" {
			status := inventoryv1.CollectionStatus(message.Get(field).Enum())
			if status == inventoryv1.CollectionStatus_COLLECTION_STATUS_NOT_APPLICABLE && inventorySeatNotApplicable(context, path, message) {
				continue
			}
			if status != truthSuccess && (status != truthUnavailable || inventoryUnavailableReason(context, path) == "") {
				return fmt.Errorf("inventory health failed for %s: %s", path, status)
			}
			continue
		}
		if field.Kind() != protoreflect.MessageKind || field.Message().ParentFile().Package() != "lindm.inventory.v1" {
			continue
		}
		if field.IsList() {
			list := message.Get(field).List()
			for j := range list.Len() {
				// Paths denote exact schema fields, not guest-controlled identities.
				if err := checkInventoryMessage(list.Get(j).Message(), name, context, requireFields); err != nil {
					return err
				}
			}
			continue
		}
		if !message.Has(field) {
			if requireFields {
				return fmt.Errorf("inventory health missing %s", name)
			}
			continue
		}
		if err := checkInventoryMessage(message.Get(field).Message(), name, context, requireFields); err != nil {
			return err
		}
	}
	return nil
}

// NOT_APPLICABLE is contextual evidence, never a global field exception.
func inventorySeatNotApplicable(context inventoryHealthContext, path string, message protoreflect.Message) bool {
	session := context.session
	seat, ok := message.Interface().(*inventoryv1.ObservedString)
	if !ok || path != "host.details.sessions.active_sessions.sessions.seat" || session == nil || seat != session.Seat || seat.Value != "" {
		return false
	}
	return session.GetSessionClass().GetStatus() == truthSuccess &&
		session.GetSessionType().GetStatus() == truthSuccess &&
		session.GetRemote().GetStatus() == truthSuccess &&
		(session.SessionClass.Value == "manager" || session.SessionClass.Value == "background" || session.Remote.Value || session.SessionType.Value == "tty")
}
