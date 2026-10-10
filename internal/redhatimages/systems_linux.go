package redhatimages

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"time"
)

const systemOrigin = apiOrigin + "/management/v1"
const systemPageSize = 100
const systemInventoryLimit = 1000

// System is an allowlisted projection of the native RHSM consumer metadata.
// Account, activation-key, entitlement and arbitrary fact data are never retained.
type System struct {
	UUID        string `json:"uuid"`
	Name        string `json:"name"`
	CreatedDate string `json:"createdDate"`
	LastCheckin string `json:"lastCheckin"`
}

// CleanupResult contains only public consumer identities and aggregate key counts.
// Deleted means an acknowledged DELETE; Absent requires a subsequent GET 404.
// The result remains useful when CleanupRegistrations returns a partial failure.
type CleanupResult struct {
	SystemsSelected     []string `json:"systemsSelected"`
	SystemsDeleted      []string `json:"systemsDeleted"`
	SystemsAbsent       []string `json:"systemsAbsent"`
	KeysSelected        int      `json:"keysSelected"`
	KeysDeleted         int      `json:"keysDeleted"`
	KeysRemaining       int      `json:"keysRemaining"`
	KeysAbsenceVerified bool     `json:"keysAbsenceVerified"`
}

func canonicalConsumerUUID(id string) bool {
	if len(id) != 36 || id == "00000000-0000-0000-0000-000000000000" {
		return false
	}
	for i := range id {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if id[i] != '-' {
				return false
			}
		} else if !lowerHexDigit(id[i]) {
			return false
		}
	}
	return true
}

func lowerHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f'
}

// systemRequest implements only the official v1 list/show/remove operations:
// https://api.access.redhat.com/management/v1/swagger.json (authenticated).
// No request uses response-provided URLs, and no mutation is retried.
func (c *Client) systemRequest(ctx context.Context, method, id string, offset int) (*http.Response, error) {
	path := "/systems"
	if id == "" {
		if method != http.MethodGet || offset < 0 || offset > systemInventoryLimit {
			return nil, errors.New("redhatimages: refused system list request")
		}
		path += "?limit=100&offset=" + strconv.Itoa(offset)
	} else {
		if !canonicalConsumerUUID(id) || (method != http.MethodGet && method != http.MethodDelete) {
			return nil, errors.New("redhatimages: refused system identity or method")
		}
		path += "/" + id
	}
	if err := c.ensureBearer(ctx); err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, method, systemOrigin+path, nil)
	if err != nil {
		return nil, errors.New("redhatimages: construct system API request failed")
	}
	request.Header.Set("Authorization", "Bearer "+c.bearer)
	request.Header.Set("Accept", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return nil, errors.New("redhatimages: system HTTPS request failed")
	}
	return response, nil
}

func (c *Client) listSystems(ctx context.Context) ([]System, error) {
	systems := make([]System, 0)
	seen := make(map[string]bool)
	for offset := 0; offset <= systemInventoryLimit; offset += systemPageSize {
		response, err := c.systemRequest(ctx, http.MethodGet, "", offset)
		if err != nil {
			return nil, err
		}
		var listed struct {
			Body []System `json:"body"`
		}
		decodeErr := decodeBounded(response.Body, &listed)
		closeErr := response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("redhatimages: system list HTTP status %d", response.StatusCode)
		}
		if err := errors.Join(decodeErr, closeErr); err != nil {
			return nil, err
		}
		if listed.Body == nil || len(listed.Body) > systemPageSize || len(systems)+len(listed.Body) > systemInventoryLimit {
			return nil, errors.New("redhatimages: invalid or oversized system inventory")
		}
		for _, system := range listed.Body {
			if !canonicalConsumerUUID(system.UUID) || seen[system.UUID] {
				return nil, errors.New("redhatimages: invalid or duplicate system identity")
			}
			seen[system.UUID] = true
			systems = append(systems, system)
		}
		if len(listed.Body) < systemPageSize {
			return systems, nil
		}
	}
	return nil, errors.New("redhatimages: system inventory exceeds pagination bound")
}

func (c *Client) readSystem(ctx context.Context, id string) (System, bool, error) {
	response, err := c.systemRequest(ctx, http.MethodGet, id, 0)
	if err != nil {
		return System{}, false, err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode == http.StatusNotFound {
		return System{}, true, nil
	}
	if response.StatusCode != http.StatusOK {
		return System{}, false, fmt.Errorf("redhatimages: system read HTTP status %d", response.StatusCode)
	}
	var found struct {
		Body System `json:"body"`
	}
	if err := decodeBounded(response.Body, &found); err != nil {
		return System{}, false, err
	}
	if found.Body.UUID != id {
		return System{}, false, errors.New("redhatimages: system detail identity mismatch")
	}
	return found.Body, false, nil
}

// InventorySystems is read-only. Details include creation time, which is absent
// from the native list. A name/time match is a candidate, not proof of ownership.
func (c *Client) InventorySystems(ctx context.Context) ([]System, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	systems, err := c.listSystems(ctx)
	if err != nil {
		return nil, err
	}
	for i := range systems {
		detail, absent, err := c.readSystem(ctx, systems[i].UUID)
		if err != nil {
			return nil, err
		}
		if absent {
			return nil, errors.New("redhatimages: system disappeared during inventory; repeat read-only inventory")
		}
		systems[i] = detail
	}
	sort.Slice(systems, func(i, j int) bool { return systems[i].UUID < systems[j].UUID })
	return systems, nil
}

// CleanupRegistrations deletes exact laboratory systems and keys only after all
// lanes stop. legacyConsumerUUID must be independently established as lab-owned;
// it is never inferred from a default hostname or creation timestamp. Empty means
// no legacy exception. Systems are re-read before deletion to reject renamed
// candidates. Every selected UUID gets a subsequent absence read, even on error.
func (c *Client) CleanupRegistrations(ctx context.Context, confirmed bool, legacyConsumerUUID string) (CleanupResult, error) {
	result := CleanupResult{
		SystemsSelected: []string{},
		SystemsDeleted:  []string{},
		SystemsAbsent:   []string{},
	}
	if !confirmed {
		return result, errors.New("redhatimages: registration cleanup requires explicit confirmation and stopped lab lanes")
	}
	if legacyConsumerUUID != "" && !canonicalConsumerUUID(legacyConsumerUUID) {
		return result, errors.New("redhatimages: legacy consumer requires an exact canonical UUID independently established as lab-owned")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	systems, err := c.listSystems(ctx)
	if err != nil {
		return result, err
	}
	keys, err := c.listRegistrations(ctx)
	if err != nil {
		return result, err
	}
	selected := make(map[string]string)
	for _, system := range systems {
		if ownedRegistration(system.Name) {
			selected[system.UUID] = system.Name
		}
	}
	if legacyConsumerUUID != "" {
		selected[legacyConsumerUUID] = ""
	}
	for id := range selected {
		result.SystemsSelected = append(result.SystemsSelected, id)
	}
	sort.Strings(result.SystemsSelected)
	result.KeysSelected = len(keys)
	var failures []error
	for _, id := range result.SystemsSelected {
		system, absent, err := c.readSystem(ctx, id)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if absent {
			continue
		}
		if id != legacyConsumerUUID && (system.Name != selected[id] || !ownedRegistration(system.Name)) {
			failures = append(failures, errors.New("redhatimages: system ownership changed before cleanup"))
			continue
		}
		response, err := c.systemRequest(ctx, http.MethodDelete, id, 0)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		closeErr := response.Body.Close()
		switch response.StatusCode {
		case http.StatusNoContent:
			result.SystemsDeleted = append(result.SystemsDeleted, id)
		case http.StatusNotFound:
		default:
			failures = append(failures, fmt.Errorf("redhatimages: system cleanup HTTP status %d", response.StatusCode))
		}
		if closeErr != nil {
			failures = append(failures, errors.New("redhatimages: system cleanup response close failed"))
		}
	}
	for _, key := range keys {
		if err := c.deleteRegistration(ctx, key); err != nil {
			failures = append(failures, err)
			continue
		}
		result.KeysDeleted++
	}
	for _, id := range result.SystemsSelected {
		_, absent, err := c.readSystem(ctx, id)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if !absent {
			failures = append(failures, errors.New("redhatimages: selected system remains after cleanup"))
			continue
		}
		result.SystemsAbsent = append(result.SystemsAbsent, id)
	}
	remaining, err := c.listRegistrations(ctx)
	if err != nil {
		failures = append(failures, err)
	} else {
		result.KeysRemaining = len(remaining)
		result.KeysAbsenceVerified = len(remaining) == 0
		if len(remaining) != 0 {
			failures = append(failures, errors.New("redhatimages: laboratory activation keys remain after cleanup"))
		}
	}
	return result, errors.Join(failures...)
}
