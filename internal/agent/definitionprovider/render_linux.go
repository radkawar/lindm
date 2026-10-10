//go:build linux

package definitionprovider

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"

	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/resource"
)

const unitRoot = "/etc/systemd/system"
const dropInName = "50-lindm.conf"

func protectedUnit(unit string) bool {
	return unit == "lindm.service" || unit == "lindm.timer" || strings.HasPrefix(unit, "lindm-")
}

func validateDesired(desired *resourcev1.ResourceDesiredState) error {
	if err := resource.ValidateDesired(desired); err != nil {
		return err
	}
	d := desired.GetSystemdDefinition()
	if d == nil {
		return ErrUnsupported
	}
	if t := d.GetTimer(); t != nil {
		if protectedUnit(t.GetUnit()) || protectedUnit(t.GetService().GetCanonicalKey()) {
			return ErrProtected
		}
		if err := resource.ValidateRef(t.GetService()); err != nil {
			return err
		}
	} else if protectedUnit(d.GetDropIn().GetUnit()) {
		return ErrProtected
	}
	return nil
}

// DefinitionPath is derived from a validated typed identity. There is no path
// override, raw unit text, native option dictionary, or executable argument arm.
func DefinitionPath(desired *resourcev1.ResourceDesiredState) (string, error) {
	if err := validateDesired(desired); err != nil {
		return "", err
	}
	if t := desired.GetSystemdDefinition().GetTimer(); t != nil {
		return unitRoot + "/" + t.GetUnit(), nil
	}
	return unitRoot + "/" + desired.GetSystemdDefinition().GetDropIn().GetUnit() + ".d/" + dropInName, nil
}

func targetUnit(d *resourcev1.SystemdDefinitionDesired) string {
	if t := d.GetTimer(); t != nil {
		return t.GetService().GetCanonicalKey()
	}
	return d.GetDropIn().GetUnit()
}

// Render produces only the closed approved directives. Monotonic timers have an
// initial OnActiveSec event as well as OnUnitActiveSec: enabling a timer does not
// start its service immediately and the initial interval is not lost when that
// service has never run. Calendar timers are UTC and do not catch up missed runs.
func Render(desired *resourcev1.ResourceDesiredState) ([]byte, error) {
	if err := validateDesired(desired); err != nil {
		return nil, err
	}
	d := desired.GetSystemdDefinition()
	if d.GetPresence() == resourcev1.Presence_PRESENCE_ABSENT {
		return nil, nil
	}
	var out strings.Builder
	out.WriteString("# Managed by lindm. Changes are ownership conflicts.\n")
	if t := d.GetTimer(); t != nil {
		out.WriteString("[Unit]\nDescription=lindm managed timer\n\n[Timer]\n")
		fmt.Fprintf(&out, "Unit=%s\n", t.GetService().GetCanonicalKey())
		if daily := t.GetSchedule().GetDaily(); daily != nil {
			fmt.Fprintf(&out, "OnCalendar=*-*-* %02d:%02d:00 UTC\n", daily.GetHour(), daily.GetMinute())
		} else {
			seconds := t.GetSchedule().GetIntervalSeconds()
			fmt.Fprintf(&out, "OnActiveSec=%ds\nOnUnitActiveSec=%ds\n", seconds, seconds)
		}
		out.WriteString("AccuracySec=1s\nRandomizedDelaySec=0\nPersistent=no\nWakeSystem=no\n\n[Install]\nWantedBy=timers.target\n")
	} else {
		drop := d.GetDropIn()
		out.WriteString("[Service]\n")
		if drop.CpuWeight != nil {
			fmt.Fprintf(&out, "CPUWeight=%d\n", drop.GetCpuWeight())
		}
		if drop.MemoryMaxBytes != nil {
			fmt.Fprintf(&out, "MemoryMax=%d\n", drop.GetMemoryMaxBytes())
		}
		if drop.TasksMax != nil {
			fmt.Fprintf(&out, "TasksMax=%d\n", drop.GetTasksMax())
		}
		if drop.NoNewPrivileges != nil {
			value := "no"
			if drop.GetNoNewPrivileges() {
				value = "yes"
			}
			fmt.Fprintf(&out, "NoNewPrivileges=%s\n", value)
		}
	}
	return []byte(out.String()), nil
}

func optionsMatch(d *resourcev1.ServiceDropIn, o *resourcev1.SystemdEffectiveOptions) bool {
	if d == nil || o == nil {
		return false
	}
	return (d.CpuWeight == nil || uint64(d.GetCpuWeight()) == o.GetCpuWeight()) &&
		(d.MemoryMaxBytes == nil || d.GetMemoryMaxBytes() == o.GetMemoryMax()) &&
		(d.TasksMax == nil || uint64(d.GetTasksMax()) == o.GetTasksMax()) &&
		(d.NoNewPrivileges == nil || d.GetNoNewPrivileges() == o.GetNoNewPrivileges())
}

// Adoption is restricted to files representable by the closed definition arm.
// Capturing an arbitrary historical ExecStart/include must not turn release into
// a raw-content execution capability.
func parseOwnedDropIn(desired *resourcev1.ResourceDesiredState, data []byte) (*resourcev1.SystemdDefinitionDesired, error) {
	const prefix = "# Managed by lindm. Changes are ownership conflicts.\n[Service]\n"
	body, ok := strings.CutPrefix(string(data), prefix)
	if !ok {
		return nil, ErrUnsupported
	}
	drop := &resourcev1.ServiceDropIn{Unit: desired.GetSystemdDefinition().GetDropIn().GetUnit()}
	for line := range strings.SplitSeq(strings.TrimSuffix(body, "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, ErrUnsupported
		}
		switch key {
		case "CPUWeight":
			v, err := strconv.ParseUint(value, 10, 32)
			if err != nil || drop.CpuWeight != nil {
				return nil, ErrUnsupported
			}
			drop.CpuWeight = proto.Uint32(uint32(v))
		case "MemoryMax":
			v, err := strconv.ParseUint(value, 10, 64)
			if err != nil || drop.MemoryMaxBytes != nil {
				return nil, ErrUnsupported
			}
			drop.MemoryMaxBytes = proto.Uint64(v)
		case "TasksMax":
			v, err := strconv.ParseUint(value, 10, 32)
			if err != nil || drop.TasksMax != nil {
				return nil, ErrUnsupported
			}
			drop.TasksMax = proto.Uint32(uint32(v))
		case "NoNewPrivileges":
			if drop.NoNewPrivileges != nil || (value != "yes" && value != "no") {
				return nil, ErrUnsupported
			}
			drop.NoNewPrivileges = proto.Bool(value == "yes")
		default:
			return nil, ErrUnsupported
		}
	}
	native := &resourcev1.SystemdDefinitionDesired{Presence: resourcev1.Presence_PRESENCE_PRESENT, Definition: &resourcev1.SystemdDefinitionDesired_DropIn{DropIn: drop}}
	d := &resourcev1.ResourceDesiredState{Ref: proto.CloneOf(desired.GetRef()), State: &resourcev1.ResourceDesiredState_SystemdDefinition{SystemdDefinition: native}}
	rendered, err := Render(d)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(rendered, data) {
		return nil, ErrUnsupported
	}
	return native, nil
}
