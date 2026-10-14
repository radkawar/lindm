// SPDX-License-Identifier: Apache-2.0

package directory

import (
	"context"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/device/core"
	"lindm/internal/device/devicedb"
	"lindm/internal/device/inventory"
	"lindm/internal/identity"
	"lindm/internal/platform"
)

const (
	defaultSuggestionPage = 50
	maxSuggestionPage     = 100
)

// suggestionPermission is the read permission of the list each field draws
// from. Unknown fields use fleet.read so a malformed request is denied exactly
// like a device read before it is rejected as invalid.
func suggestionPermission(field adminv1.SuggestionField) identity.Permission {
	if field == adminv1.SuggestionField_SUGGESTION_FIELD_DIRECTORY_GROUP {
		return identity.PermissionManageAccounts
	}
	return identity.PermissionReadFleet
}

// SuggestValues lists recorded values of one field so administrators choose
// instead of typing them. Values match an ASCII case-insensitive literal
// prefix, sort by (lowercase, exact) byte order and resume strictly after the
// previous page's last value. Device fields honor the caller's fleet.read
// device scope and count distinct devices; directory groups are deployment-wide
// identity data and require an unrestricted accounts.manage grant.
func (s *Service) SuggestValues(ctx context.Context, req *connect.Request[adminv1.SuggestValuesRequest]) (*connect.Response[adminv1.SuggestValuesResponse], error) {
	ctx, cancel := core.Bound(ctx)
	defer cancel()
	var field adminv1.SuggestionField
	if req != nil && req.Msg != nil {
		field = req.Msg.GetField()
	}
	perm := suggestionPermission(field)
	var actor identity.Principal
	var err error
	if field == adminv1.SuggestionField_SUGGESTION_FIELD_DIRECTORY_GROUP {
		actor, err = s.RequireUnrestricted(ctx, perm)
	} else {
		actor, err = s.Require(ctx, perm)
	}
	if err != nil {
		return nil, err
	}
	if req == nil || req.Msg == nil || s.Rules.Validate(req.Msg) != nil {
		return nil, core.Invalid("invalid_argument")
	}
	msg := req.Msg
	if err := checkSuggestionNarrowing(msg); err != nil {
		return nil, err
	}
	var deviceID uuid.UUID
	if msg.GetDeviceId() != "" {
		if deviceID, err = core.ParseUUID(msg.GetDeviceId()); err != nil {
			return nil, core.Invalid("invalid_id")
		}
	}
	unrestricted, scopes, err := core.DeviceScopeFilter(actor, perm)
	if err != nil {
		return nil, core.MapErr(err)
	}
	if err := s.Acquire(ctx); err != nil {
		return nil, core.MapErr(err)
	}
	defer s.Release()
	limit := int32(defaultSuggestionPage)
	if size := msg.GetPageSize(); size > 0 {
		limit = int32(min(size, maxSuggestionPage))
	}
	query := suggestionQuery{
		field: field, prefix: asciiLower(msg.GetPrefix()), after: msg.GetAfter(), limit: limit + 1,
		osID: msg.GetOsId(), manager: msg.GetManager(),
		unrestricted: unrestricted, scopes: scopes, deviceID: deviceID, hasDevice: deviceID != uuid.Nil,
	}
	var values []*adminv1.Suggestion
	err = s.Within(ctx, func(ctx context.Context, q *devicedb.Queries) error {
		if query.hasDevice {
			if err := core.RequireDeviceScope(ctx, q, actor, perm, deviceID); err != nil {
				return err
			}
		}
		var runErr error
		values, runErr = query.run(ctx, q)
		return runErr
	})
	if err != nil {
		return nil, core.MapErr(err)
	}
	response := &adminv1.SuggestValuesResponse{Suggestions: values}
	if len(values) > int(limit) {
		response.Suggestions = values[:limit]
		response.NextAfter = values[limit-1].GetValue()
	}
	return core.NoStore(response), nil
}

// checkSuggestionNarrowing rejects qualifiers a field does not define rather
// than silently ignoring them.
func checkSuggestionNarrowing(msg *adminv1.SuggestValuesRequest) error {
	field := msg.GetField()
	switch {
	case msg.GetOsId() != "" && field != adminv1.SuggestionField_SUGGESTION_FIELD_OS_VERSION,
		msg.GetManager() != "" && field != adminv1.SuggestionField_SUGGESTION_FIELD_PACKAGE_NAME,
		msg.GetDeviceId() != "" && field == adminv1.SuggestionField_SUGGESTION_FIELD_DIRECTORY_GROUP:
		return core.Invalid("unsupported_narrowing")
	case msg.GetDeviceId() == "" && field == adminv1.SuggestionField_SUGGESTION_FIELD_PACKAGE_MANAGER:
		return core.Invalid("device_required")
	}
	return nil
}

type suggestionQuery struct {
	field        adminv1.SuggestionField
	prefix       string
	after        string
	limit        int32
	osID         string
	manager      string
	unrestricted bool
	scopes       []byte
	deviceID     uuid.UUID
	hasDevice    bool
}

func (s suggestionQuery) run(ctx context.Context, q *devicedb.Queries) ([]*adminv1.Suggestion, error) {
	switch s.field {
	case adminv1.SuggestionField_SUGGESTION_FIELD_OS_ID:
		return s.deviceColumn(ctx, q, "os_id")
	case adminv1.SuggestionField_SUGGESTION_FIELD_OS_VERSION:
		return s.deviceColumn(ctx, q, "os_version")
	case adminv1.SuggestionField_SUGGESTION_FIELD_ARCHITECTURE:
		return s.deviceColumn(ctx, q, "architecture")
	case adminv1.SuggestionField_SUGGESTION_FIELD_DEVICE_LABEL:
		rows, err := q.SuggestDeviceLabels(ctx, devicedb.SuggestDeviceLabelsParams{
			ScopeUnrestricted: s.unrestricted, Scopes: s.scopes, HasDevice: s.hasDevice, DeviceID: s.deviceID,
			Prefix: s.prefix, After: s.after, RowLimit: s.limit,
		})
		return suggestions(rows, err, func(r devicedb.SuggestDeviceLabelsRow) (string, int64) { return r.Value, r.Count })
	case adminv1.SuggestionField_SUGGESTION_FIELD_AGENT_RELEASE:
		rows, err := q.SuggestAgentReleases(ctx, devicedb.SuggestAgentReleasesParams{
			ScopeUnrestricted: s.unrestricted, Scopes: s.scopes, HasDevice: s.hasDevice, DeviceID: s.deviceID,
			Prefix: s.prefix, After: s.after, RowLimit: s.limit,
		})
		return suggestions(rows, err, func(r devicedb.SuggestAgentReleasesRow) (string, int64) { return r.Value, r.Count })
	case adminv1.SuggestionField_SUGGESTION_FIELD_PACKAGE_NAME:
		if s.hasDevice {
			snapshot, ok, err := currentSnapshot(ctx, q, s.deviceID)
			if err != nil || !ok {
				return nil, err
			}
			rows, err := q.SuggestSnapshotPackageNames(ctx, devicedb.SuggestSnapshotPackageNamesParams{
				SnapshotID: snapshot, Prefix: s.prefix, After: s.after, Manager: s.manager, RowLimit: s.limit,
			})
			return suggestions(rows, err, func(r devicedb.SuggestSnapshotPackageNamesRow) (string, int64) { return r.Value, r.Count })
		}
		startLower, startExact, end, bounded := s.indexRange()
		rows, err := q.SuggestPackageNames(ctx, devicedb.SuggestPackageNamesParams{
			ScopeUnrestricted: s.unrestricted, Scopes: s.scopes, StartLower: startLower, StartExact: startExact,
			Unbounded: !bounded, PrefixEnd: end, Manager: s.manager, RowLimit: s.limit,
		})
		return suggestions(rows, err, func(r devicedb.SuggestPackageNamesRow) (string, int64) { return r.Value, r.Count })
	case adminv1.SuggestionField_SUGGESTION_FIELD_LOCAL_USER_NAME:
		return s.hostValues(ctx, q, inventory.HostValueLocalUser)
	case adminv1.SuggestionField_SUGGESTION_FIELD_LOGIN_SHELL:
		return s.hostValues(ctx, q, inventory.HostValueShell)
	case adminv1.SuggestionField_SUGGESTION_FIELD_FLATPAK_APP:
		return s.hostValues(ctx, q, inventory.HostValueFlatpak)
	case adminv1.SuggestionField_SUGGESTION_FIELD_SNAP_NAME:
		return s.hostValues(ctx, q, inventory.HostValueSnap)
	case adminv1.SuggestionField_SUGGESTION_FIELD_PACKAGE_MANAGER:
		snapshot, ok, err := currentSnapshot(ctx, q, s.deviceID)
		if err != nil || !ok {
			return nil, err
		}
		rows, err := q.SuggestSnapshotPackageManagers(ctx, devicedb.SuggestSnapshotPackageManagersParams{
			SnapshotID: snapshot, Prefix: s.prefix, After: s.after, RowLimit: s.limit,
		})
		return suggestions(rows, err, func(r devicedb.SuggestSnapshotPackageManagersRow) (string, int64) { return r.Value, r.Count })
	case adminv1.SuggestionField_SUGGESTION_FIELD_DIRECTORY_GROUP:
		rows, err := q.SuggestDirectoryGroups(ctx, devicedb.SuggestDirectoryGroupsParams{Prefix: s.prefix, After: s.after, RowLimit: s.limit})
		return suggestions(rows, err, func(r devicedb.SuggestDirectoryGroupsRow) (string, int64) { return r.Value, r.Count })
	case adminv1.SuggestionField_SUGGESTION_FIELD_ADVISORY_ID:
		rows, err := q.SuggestAdvisoryIDs(ctx, devicedb.SuggestAdvisoryIDsParams{
			ScopeUnrestricted: s.unrestricted, Scopes: s.scopes, HasDevice: s.hasDevice, DeviceID: s.deviceID,
			Prefix: s.prefix, After: s.after, RowLimit: s.limit,
		})
		return suggestions(rows, err, func(r devicedb.SuggestAdvisoryIDsRow) (string, int64) { return r.Value, r.Count })
	case adminv1.SuggestionField_SUGGESTION_FIELD_CVE_ID:
		rows, err := q.SuggestCVEIDs(ctx, devicedb.SuggestCVEIDsParams{
			ScopeUnrestricted: s.unrestricted, Scopes: s.scopes, HasDevice: s.hasDevice, DeviceID: s.deviceID,
			Prefix: s.prefix, After: s.after, RowLimit: s.limit,
		})
		return suggestions(rows, err, func(r devicedb.SuggestCVEIDsRow) (string, int64) { return r.Value, r.Count })
	}
	return nil, core.Invalid("invalid_argument")
}

// indexRange is the exclusive start key and prefix end of an index walk: the
// later of (prefix, "") and the previous page's (lower(after), after). One row
// comparison narrows the btree start; a second lower bound would not.
func (s suggestionQuery) indexRange() (startLower, startExact, end string, bounded bool) {
	startLower = s.prefix
	if lower := asciiLower(s.after); lower > s.prefix || (lower == s.prefix && s.after != "") {
		startLower, startExact = lower, s.after
	}
	end, bounded = prefixEnd(s.prefix)
	return startLower, startExact, end, bounded
}

func (s suggestionQuery) hostValues(ctx context.Context, q *devicedb.Queries, kind inventory.HostValueKind) ([]*adminv1.Suggestion, error) {
	startLower, startExact, end, bounded := s.indexRange()
	rows, err := q.SuggestHostInventoryValues(ctx, devicedb.SuggestHostInventoryValuesParams{
		Kind: int16(kind), StartLower: startLower, StartExact: startExact, Unbounded: !bounded, PrefixEnd: end,
		ScopeUnrestricted: s.unrestricted, Scopes: s.scopes, HasDevice: s.hasDevice, DeviceID: s.deviceID, RowLimit: s.limit,
	})
	return suggestions(rows, err, func(r devicedb.SuggestHostInventoryValuesRow) (string, int64) { return r.Value, r.Count })
}

func (s suggestionQuery) deviceColumn(ctx context.Context, q *devicedb.Queries, column string) ([]*adminv1.Suggestion, error) {
	rows, err := q.SuggestDeviceValues(ctx, devicedb.SuggestDeviceValuesParams{
		Field: column, ScopeUnrestricted: s.unrestricted, Scopes: s.scopes, HasDevice: s.hasDevice, DeviceID: s.deviceID,
		OsID: s.osID, Prefix: s.prefix, After: s.after, RowLimit: s.limit,
	})
	values, err := suggestions(rows, err, func(r devicedb.SuggestDeviceValuesRow) (string, int64) { return r.Value, r.Count })
	if err != nil {
		return nil, err
	}
	for _, value := range values {
		value.Label = s.osLabel(column, value.GetValue())
	}
	return values, nil
}

// osLabel names registered operating systems so administrators choose
// "Ubuntu 24.04 LTS" rather than raw os-release IDs. A version is named only
// when os_id narrows it; alone it does not identify a release.
func (s suggestionQuery) osLabel(column, value string) string {
	switch column {
	case "os_id":
		for _, release := range platform.Releases() {
			if release.ID == value {
				return release.Distribution
			}
		}
	case "os_version":
		if release := platform.Identify(platform.OSRelease{ID: s.osID, VersionID: value}); s.osID != "" && release.Known() {
			return release.Name
		}
	}
	return ""
}

// currentSnapshot is the device's published package snapshot; a device that
// has none has no package values rather than an error.
func currentSnapshot(ctx context.Context, q *devicedb.Queries, deviceID uuid.UUID) (uuid.UUID, bool, error) {
	detail, err := q.GetDeviceDetail(ctx, deviceID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return uuid.Nil, false, core.ErrNotFound
		}
		return uuid.Nil, false, err
	}
	if detail.CurrentSnapshotID == nil {
		return uuid.Nil, false, nil
	}
	return *detail.CurrentSnapshotID, true, nil
}

func suggestions[Row any](rows []Row, err error, read func(Row) (string, int64)) ([]*adminv1.Suggestion, error) {
	if err != nil {
		return nil, err
	}
	out := make([]*adminv1.Suggestion, 0, len(rows))
	for _, row := range rows {
		value, count := read(row)
		if count < 0 {
			return nil, core.ErrInternalState
		}
		out = append(out, &adminv1.Suggestion{Value: value, Count: uint64(count)})
	}
	return out, nil
}

// asciiLower matches PostgreSQL lower() under the "C" collation, which folds
// only ASCII letters.
func asciiLower(value string) string {
	out := []byte(value)
	for i, b := range out {
		if 'A' <= b && b <= 'Z' {
			out[i] = b + ('a' - 'A')
		}
	}
	return string(out)
}

// prefixEnd is the least string greater than every string starting with
// prefix in byte order, which for valid UTF-8 is code point order. It is
// unbounded (false) for an empty prefix or one made only of U+10FFFF.
func prefixEnd(prefix string) (string, bool) {
	runes := []rune(prefix)
	for i := len(runes) - 1; i >= 0; i-- {
		next := runes[i] + 1
		if next == 0xD800 {
			next = 0xE000
		}
		if next <= 0x10FFFF {
			return string(runes[:i]) + string(next), true
		}
	}
	return "", false
}
