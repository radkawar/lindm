package redhatimages

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const consumerOne = "11111111-1111-4111-8111-111111111111"
const consumerTwo = "22222222-2222-4222-8222-222222222222"

func TestSystemCleanupExactOwnershipAndPostcondition(t *testing.T) {
	owned := registrationPrefix + strings.Repeat("a", 32)
	f := &registrationFixture{systems: map[string]System{
		consumerOne: {UUID: consumerOne, Name: owned},
		consumerTwo: {UUID: consumerTwo, Name: "localhost.localdomain"},
	}, keys: map[string]bool{owned: true, "customer-key": true}}
	client := registrationClient(t, f)
	result, err := client.CleanupRegistrations(context.Background(), true, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(result.SystemsSelected) != 1 || len(result.SystemsDeleted) != 1 || len(result.SystemsAbsent) != 1 || result.SystemsAbsent[0] != consumerOne || result.KeysDeleted != 1 || !result.KeysAbsenceVerified {
		t.Fatal("cleanup evidence lacks exact identities or absence")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.systems) != 1 || f.systems[consumerTwo].Name != "localhost.localdomain" || f.systemReads != 2 || len(f.systemDeletes) != 1 || f.badBearer {
		t.Fatal("cleanup touched foreign system or did not verify absence")
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{owned, "customer-key", "private-key", "private-account"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatal("cleanup evidence leaks private metadata")
		}
	}
}

func TestSystemCleanupRejectsForeignNames(t *testing.T) {
	for _, name := range []string{"localhost.localdomain", "customer", registrationPrefix + "short", registrationPrefix + strings.Repeat("A", 32), registrationPrefix + strings.Repeat("a", 33), "x" + registrationPrefix + strings.Repeat("a", 32), registrationPrefix + strings.Repeat("g", 32), registrationPrefix + strings.Repeat("a", 32) + "/other"} {
		t.Run(name, func(t *testing.T) {
			f := &registrationFixture{systems: map[string]System{consumerOne: {UUID: consumerOne, Name: name}}}
			result, err := registrationClient(t, f).CleanupRegistrations(context.Background(), true, "")
			if err != nil || len(result.SystemsSelected) != 0 || len(f.systemDeletes) != 0 {
				t.Fatal("foreign system selected")
			}
		})
	}
}

func TestSystemCleanupLegacyRequiresExactCanonicalUUID(t *testing.T) {
	for _, id := range []string{"localhost.localdomain", "11111111111141118111111111111111", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", "00000000-0000-0000-0000-000000000000", consumerOne + "/other", " " + consumerOne} {
		f := new(registrationFixture)
		client := registrationClient(t, f)
		if _, err := client.CleanupRegistrations(context.Background(), true, id); err == nil {
			t.Fatal("malformed legacy UUID accepted")
		}
		if len(f.systemDeletes) != 0 || f.systemReads != 0 {
			t.Fatal("invalid legacy UUID reached system API")
		}
	}
	f := &registrationFixture{systems: map[string]System{
		consumerOne: {UUID: consumerOne, Name: "localhost.localdomain"},
		consumerTwo: {UUID: consumerTwo, Name: "localhost.localdomain"},
	}}
	client := registrationClient(t, f)
	if _, err := client.CleanupRegistrations(context.Background(), false, consumerOne); err == nil {
		t.Fatal("legacy cleanup bypassed confirmation")
	}
	result, err := client.CleanupRegistrations(context.Background(), true, consumerOne)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.SystemsAbsent) != 1 || result.SystemsAbsent[0] != consumerOne || len(f.systemDeletes) != 1 || f.systemDeletes[0] != consumerOne || len(f.systems) != 1 {
		t.Fatal("legacy UUID expanded to hostname deletion")
	}
}

func TestSystemCleanupPartialFailurePreservesEvidenceAndCleansKeys(t *testing.T) {
	owned := registrationPrefix + strings.Repeat("b", 32)
	f := &registrationFixture{systems: map[string]System{
		consumerOne: {UUID: consumerOne, Name: owned},
		consumerTwo: {UUID: consumerTwo, Name: owned},
	}, keys: map[string]bool{owned: true}, systemFailure: consumerOne}
	result, err := registrationClient(t, f).CleanupRegistrations(context.Background(), true, "")
	if err == nil || strings.Contains(err.Error(), "private-native-error") {
		t.Fatal("partial failure hidden or native response leaked")
	}
	if len(f.systemDeletes) != 2 || len(result.SystemsAbsent) != 1 || result.SystemsAbsent[0] != consumerTwo || result.KeysDeleted != 1 || !result.KeysAbsenceVerified {
		t.Fatal("partial failure skipped independent cleanup or retried mutation")
	}
}

func TestSystemCleanupRequiresObservedAbsence(t *testing.T) {
	owned := registrationPrefix + strings.Repeat("c", 32)
	f := &registrationFixture{systems: map[string]System{consumerOne: {UUID: consumerOne, Name: owned}}, keys: map[string]bool{owned: true}, keepSystem: true, keepKey: true}
	result, err := registrationClient(t, f).CleanupRegistrations(context.Background(), true, "")
	if err == nil || len(result.SystemsDeleted) != 1 || len(result.SystemsAbsent) != 0 || result.KeysAbsenceVerified || result.KeysRemaining != 1 || len(f.systemDeletes) != 1 || f.deleted != 1 {
		t.Fatal("successful DELETE incorrectly substituted for absence or retried")
	}
}

func TestSystemCleanupRejectsRenamedCandidate(t *testing.T) {
	f := &registrationFixture{systems: map[string]System{consumerOne: {UUID: consumerOne, Name: registrationPrefix + strings.Repeat("d", 32)}}, renameSystem: "customer-system"}
	result, err := registrationClient(t, f).CleanupRegistrations(context.Background(), true, "")
	if err == nil || len(result.SystemsAbsent) != 0 || len(f.systemDeletes) != 0 {
		t.Fatal("renamed candidate deleted")
	}
}

func TestSystemCleanupAlreadyAbsentLegacy(t *testing.T) {
	f := new(registrationFixture)
	result, err := registrationClient(t, f).CleanupRegistrations(context.Background(), true, consumerOne)
	if err != nil || len(result.SystemsDeleted) != 0 || len(result.SystemsAbsent) != 1 || len(f.systemDeletes) != 0 || f.systemReads != 2 {
		t.Fatal("already absent legacy system lacks independently observed absence")
	}
}

func TestInventorySystemsReadOnlyAndSafeProjection(t *testing.T) {
	f := &registrationFixture{systems: map[string]System{consumerOne: {UUID: consumerOne, Name: "localhost.localdomain", CreatedDate: "2026-10-10T02:42:15.000Z", LastCheckin: "2026-10-10T02:42:16.000Z"}}}
	systems, err := registrationClient(t, f).InventorySystems(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(systems) != 1 || systems[0].CreatedDate == "" || systems[0].LastCheckin == "" || len(f.systemDeletes) != 0 || f.created != 0 || f.deleted != 0 {
		t.Fatal("inventory incomplete or mutated resources")
	}
	data, _ := json.Marshal(systems)
	if strings.Contains(string(data), "private-") {
		t.Fatal("inventory retained secret response fields")
	}
}

func TestSystemInventoryPaginationAndBounds(t *testing.T) {
	for _, count := range []int{100, 101, 1000, 1001} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			f := &registrationFixture{systems: make(map[string]System)}
			for i := range count {
				id := fmt.Sprintf("%08x-1111-4111-8111-111111111111", i)
				f.systems[id] = System{UUID: id, Name: "foreign"}
			}
			rows, err := registrationClient(t, f).listSystems(context.Background())
			if count <= systemInventoryLimit && (err != nil || len(rows) != count) {
				t.Fatal("bounded pagination lost entries")
			}
			if count > systemInventoryLimit && err == nil {
				t.Fatal("oversized inventory accepted")
			}
		})
	}
}

func TestSystemCleanupInvalidInventoryNeverMutates(t *testing.T) {
	owned := registrationPrefix + strings.Repeat("e", 32)
	for _, id := range []string{"bad-id", consumerOne + "/other", strings.ToUpper("abcdefab-cdef-4abc-8abc-abcdefabcdef")} {
		f := &registrationFixture{systems: map[string]System{id: {UUID: id, Name: owned}}, keys: map[string]bool{owned: true}}
		if _, err := registrationClient(t, f).CleanupRegistrations(context.Background(), true, ""); err == nil {
			t.Fatal("invalid system inventory accepted")
		}
		if len(f.systemDeletes) != 0 || f.deleted != 0 {
			t.Fatal("invalid inventory partially mutated resources")
		}
	}
	f := &registrationFixture{systems: make(map[string]System), repeatPage: true}
	for i := range 100 {
		id := fmt.Sprintf("%08x-1111-4111-8111-111111111111", i)
		f.systems[id] = System{UUID: id, Name: owned}
	}
	if _, err := registrationClient(t, f).CleanupRegistrations(context.Background(), true, ""); err == nil {
		t.Fatal("repeating API page accepted")
	}
	if len(f.systemDeletes) != 0 {
		t.Fatal("repeating page mutated resources")
	}
}
