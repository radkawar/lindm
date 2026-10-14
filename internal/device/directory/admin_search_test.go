// SPDX-License-Identifier: Apache-2.0

package directory

import (
	"encoding/csv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
)

func csvRow(t *testing.T, item *adminv1.Device) map[string]string {
	t.Helper()
	encoded, err := exportDeviceRow(item, adminv1.DeviceExportFormat_DEVICE_EXPORT_FORMAT_CSV)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(strings.NewReader(deviceCSVHeader + string(encoded))).ReadAll()
	if err != nil || len(rows) != 2 || len(rows[0]) != len(rows[1]) {
		t.Fatalf("CSV row does not match its header: %v %q", err, rows)
	}
	row := make(map[string]string)
	for i, name := range rows[0] {
		row[name] = rows[1][i]
	}
	return row
}

func TestDeviceCSVUsesHumanValues(t *testing.T) {
	seen := time.Date(2026, 10, 12, 9, 30, 5, 0, time.UTC)
	row := csvRow(t, &adminv1.Device{
		Id: uuid.NewString(), Hostname: "ubuntu-ws-01", OsId: "ubuntu", OsVersion: "24.04", Architecture: "amd64",
		LifecycleState: adminv1.DeviceState_DEVICE_STATE_ACTIVE, EnrolledAt: timestamppb.New(seen.Add(-time.Hour)), LastSeenAt: timestamppb.New(seen),
		Compliance: adminv1.DeviceCompliance_DEVICE_COMPLIANCE_ATTENTION, RootEncryption: adminv1.DeviceRootEncryption_DEVICE_ROOT_ENCRYPTION_NOT_ENCRYPTED,
		Metadata: &adminv1.DeviceMetadata{Labels: []string{"engineering", "pilot"}, Owner: &adminv1.DeviceMetadata_OwnerText{OwnerText: "Ada"}, Attributes: map[string]*adminv1.AttributeValue{
			"floor":       {Value: &adminv1.AttributeValue_IntValue{IntValue: 3}},
			"cost-center": {Value: &adminv1.AttributeValue_StringValue{StringValue: "R&D"}},
			"loaner":      {Value: &adminv1.AttributeValue_BoolValue{BoolValue: true}},
		}},
		Updates:  &adminv1.DeviceUpdateStatus{PendingUpdates: 4},
		Findings: &adminv1.DeviceFindingCounts{High: 2},
	})
	for column, want := range map[string]string{
		"Operating system": "Ubuntu 24.04 LTS", "State": "Active", "Compliance": "Needs attention", "Root encryption": "Not encrypted",
		"Last contact (UTC)": "2026-10-12 09:30:05", "Labels": "engineering; pilot", "Owner": "Ada",
		"Attributes": "cost-center: R&D; floor: 3; loaner: Yes", "Pending updates": "4", "Reboot required": "No",
		"Critical findings": "0", "High findings": "2", "Findings coverage": "Complete", "Last verified (UTC)": "Never",
	} {
		if row[column] != want {
			t.Errorf("%s = %q, want %q", column, row[column], want)
		}
	}
	for column, value := range row {
		if strings.Contains(value, "DEVICE_") || strings.Contains(value, "{") {
			t.Errorf("%s exposes a raw enum or JSON: %q", column, value)
		}
	}
}

func TestDeviceCSVDistinguishesUncheckedFromZero(t *testing.T) {
	row := csvRow(t, &adminv1.Device{Id: uuid.NewString(), LifecycleState: adminv1.DeviceState_DEVICE_STATE_PENDING, EnrolledAt: timestamppb.Now()})
	for column, want := range map[string]string{
		"Operating system": "Not reported", "State": "Pending approval", "Last contact (UTC)": "Never", "Pending updates": "Not reported",
		"Critical findings": "Not checked", "Findings coverage": "Not checked", "Root encryption": "Unknown",
	} {
		if row[column] != want {
			t.Errorf("%s = %q, want %q", column, row[column], want)
		}
	}
}

func TestSortCursorRoundTripAndRejection(t *testing.T) {
	id := uuid.New()
	for _, test := range []struct {
		last bool
		key  string
	}{{false, "alpha"}, {true, ""}, {false, strings.Repeat("é", 80)}, {false, "debian\x0112"}} {
		position, err := encodeSortCursor(test.last, test.key, id)
		if err != nil || len(position) > 512-37 {
			t.Fatalf("encode %q: len=%d err=%v", test.key, len(position), err)
		}
		last, key, decoded, err := decodeSortCursor(position)
		if err != nil || last != test.last || key != test.key || decoded != id {
			t.Fatalf("round trip %q: %v %q %v %v", test.key, last, key, decoded, err)
		}
	}
	if _, err := encodeSortCursor(false, strings.Repeat("x", maxSortKeyBytes+1), id); err == nil {
		t.Fatal("oversized key encoded")
	}
	valid, _ := encodeSortCursor(false, "k", id)
	for _, bad := range []string{"", "!!", valid[:len(valid)-8], "AQ"} {
		if _, _, _, err := decodeSortCursor(bad); err == nil {
			t.Fatalf("malformed cursor %q accepted", bad)
		}
	}
}
