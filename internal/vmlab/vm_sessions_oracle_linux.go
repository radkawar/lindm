//go:build linux

package vmlab

import (
	"errors"
	"strings"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

// loginctl's property presentation is independent of the agent's busctl JSON
// decoder. A session is included only when logind explicitly reports Active=yes.
func (o vmInventoryOracle) activeSessions(rows [][]string, status inventoryv1.CollectionStatus) (*inventoryv1.ActiveSessions, error) {
	result := &inventoryv1.ActiveSessions{Status: status}
	if status != truthSuccess {
		return result, nil
	}
	for _, row := range rows {
		if len(row) == 0 {
			return nil, errors.New("native session list has no session identifier")
		}
		data, observed, err := o.optional("loginctl", "loginctl show-session --all --no-pager -p Active -p Name -p Class -p Type -p Seat -p Remote -- "+nativeQuote(row[0]))
		if err != nil {
			return nil, err
		}
		if observed != truthSuccess {
			return &inventoryv1.ActiveSessions{Status: observed}, nil
		}
		session, err := parseTruthActiveSession(data)
		if err != nil {
			return nil, err
		}
		if session != nil {
			result.Sessions = append(result.Sessions, session)
		}
	}
	return result, nil
}

func parseTruthActiveSession(data []byte) (*inventoryv1.ActiveSession, error) {
	lines, err := truthLines(data)
	if err != nil {
		return nil, err
	}
	properties := make(map[string]string, 6)
	for _, line := range lines {
		name, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, errors.New("invalid native session property")
		}
		switch name {
		case "Active", "Name", "Class", "Type", "Seat", "Remote":
		default:
			return nil, errors.New("unexpected native session property")
		}
		if _, duplicate := properties[name]; duplicate {
			return nil, errors.New("duplicate native session property")
		}
		properties[name] = value
	}
	switch properties["Active"] {
	case "no":
		return nil, nil
	case "yes":
	default:
		return nil, errors.New("missing or invalid native active-session state")
	}
	remote := &inventoryv1.ObservedBool{Status: truthUnavailable}
	if value, exists := properties["Remote"]; exists {
		switch value {
		case "yes", "no":
			remote = truthBool(value == "yes")
		default:
			return nil, errors.New("invalid native remote-session state")
		}
	}
	session := &inventoryv1.ActiveSession{
		UserName:     truthString(properties["Name"]),
		SessionClass: truthString(properties["Class"]),
		SessionType:  truthString(properties["Type"]),
		Seat:         truthString(properties["Seat"]),
		Remote:       remote,
	}
	// A seat independently does not apply to manager, background, remote or
	// tty sessions when that context was read natively.
	class, kind := session.GetSessionClass(), session.GetSessionType()
	if session.GetSeat().GetStatus() == truthUnavailable && class.GetStatus() == truthSuccess &&
		kind.GetStatus() == truthSuccess && remote.GetStatus() == truthSuccess &&
		(class.GetValue() == "manager" || class.GetValue() == "background" || remote.GetValue() || kind.GetValue() == "tty") {
		session.Seat.Status = inventoryv1.CollectionStatus_COLLECTION_STATUS_NOT_APPLICABLE
	}
	return session, nil
}
