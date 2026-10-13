//go:build linux

package vmlab

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Capability evidence cannot be substituted by historical baseline screenshots,
// command acceptance, or another session's otherwise valid witness.
func verifyAssistanceCapabilityWitness(scenario *assistanceScenarioEvidence, witness *assistanceCapabilityWitness) error {
	if witness.Capability != scenario.Name || witness.SessionID != scenario.SessionID || witness.Guest == nil || len(witness.Checks) == 0 {
		return errors.New("capability witness is incomplete or belongs to another session")
	}
	if err := verifyAssistanceFixtureIdentity(witness.Guest, scenario.LocalSession); err != nil {
		return err
	}
	for _, path := range witness.Screenshots {
		if !slices.Contains(scenario.Screenshots, path) {
			return fmt.Errorf("capability witness references unrelated screenshot %s", path)
		}
	}
	for _, command := range witness.Commands {
		if !vmValidID(command.RequestID) || command.Status != "ASSISTANCE_COMMAND_STATUS_SUCCEEDED" {
			return errors.New("capability witness contains an incomplete command")
		}
	}
	guest := witness.Guest
	switch scenario.Name {
	case "clipboard":
		if len(witness.OperatorNonce) != 24 || witness.PastedOperatorNonce != witness.OperatorNonce || len(guest.ClipboardSource) != 24 || guest.ClipboardSource == witness.OperatorNonce || len(witness.Commands) != 2 || witness.Commands[1].Text != guest.ClipboardSource {
			return errors.New("clipboard witness lacks independent native roundtrip nonces")
		}
		if witness.Commands[0].Kind != "ASSISTANCE_COMMAND_KIND_CLIPBOARD_WRITE" || witness.Commands[1].Kind != "ASSISTANCE_COMMAND_KIND_CLIPBOARD_READ" {
			return errors.New("clipboard witness contains unrelated command outcomes")
		}
	case "clipboard-limited":
		if len(witness.OperatorNonce) != 24 || witness.PastedOperatorNonce != witness.OperatorNonce || len(witness.Commands) != 1 || witness.Commands[0].Kind != "ASSISTANCE_COMMAND_KIND_CLIPBOARD_WRITE" {
			return errors.New("limited clipboard witness lacks a real guest paste")
		}
	case "keyboard":
		if fixtureSymbols(guest) != "yzzyz" || !slices.Contains(guest.Closed, 0) || len(witness.Commands) != 1 {
			return errors.New("keyboard witness lacks mismatched-layout delivery or native window-close effect")
		}
		if !fixtureUnicodeKey(guest, "EuroSign", 0x20ac, "y") || !fixtureUnicodeKey(guest, "Cyrillic_ya", 0x44f, "Cyrillic_ya") {
			return errors.New("keyboard witness lacks canonical Euro/Cyrillic native layout effects")
		}
		if witness.Commands[0].Kind != "ASSISTANCE_COMMAND_KIND_SPECIAL_KEYS" {
			return errors.New("keyboard witness contains an unrelated command outcome")
		}
	case "display":
		if len(guest.Clicks) != 6 || len(witness.Checks) != 6 || witness.Checks[0] != "limited-display-monitor-selection-disabled" {
			return errors.New("display witness lacks a pointer observation for every presentation mode")
		}
		for i, click := range guest.Clicks[1:] {
			x, y := 0.3, 0.7
			if i%2 == 1 {
				x, y = 0.65, 0.4
			}
			if err := verifyAssistancePointer(click, 0, x, y); err != nil {
				return err
			}
		}
	case "monitors":
		if len(guest.Monitors) != 2 || len(witness.Displays) != 2 || len(witness.MonitorSelections) != 2 || len(guest.Clicks) != 3 || len(witness.Commands) == 0 {
			return errors.New("monitor witness lacks two native monitors and selected-head pointer observations")
		}
		if witness.MonitorSelections[0].Head == witness.MonitorSelections[1].Head {
			return errors.New("monitor witness selected the same native head twice")
		}
		for _, command := range witness.Commands {
			if command.Kind != "ASSISTANCE_COMMAND_KIND_SELECT_DISPLAY" {
				return errors.New("monitor witness contains an unrelated command outcome")
			}
		}
		for i, selection := range witness.MonitorSelections {
			if selection.Head < 0 || selection.Head > 1 || selection.Label == "" {
				return errors.New("invalid selected monitor")
			}
			if len(selection.Nonce) != 24 || selection.Nonce != guest.ClipboardSource {
				return errors.New("selected monitor lacks its streamed native marker")
			}
			if err := verifyAssistancePointer(guest.Clicks[i+1], selection.Head, 0.7, 0.7); err != nil {
				return err
			}
		}
	case "message":
		if err := verifyAssistanceActor(scenario, witness.MessageActor); err != nil {
			return err
		}
		if len(witness.OperatorNonce) != 24 || !assistanceMessageVisible(witness.OCR, witness.MessageActor.Display, witness.OperatorNonce) || witness.MessageScreenshot == "" || !slices.Contains(witness.Screenshots, witness.MessageScreenshot) || len(witness.Commands) != 1 {
			return errors.New("message witness lacks authenticated sender, product and nonce in the same guest screenshot")
		}
		if witness.Commands[0].Kind != "ASSISTANCE_COMMAND_KIND_MESSAGE" {
			return errors.New("message witness contains an unrelated command outcome")
		}
	default:
		return errors.New("unknown capability witness")
	}
	return nil
}

func verifyAssistanceFixtureIdentity(guest *assistanceFixtureState, local *assistanceLocalEvidence) error {
	if guest == nil || local == nil || guest.Backend != "GdkWaylandDisplay" || guest.Display == "" || guest.SessionType != "wayland" || guest.PID <= 0 || guest.UID != local.UID || guest.SessionID != local.LogindSessionID {
		return errors.New("native witness is not on the consented user's Wayland display")
	}
	return nil
}

// assistanceMessageVisible requires the product, the message label and the
// nonce directly after its authenticated sender, the sender starting an OCR
// line: "sender:" alone with the nonce opening the next line, or
// "sender: nonce" on one line, as GNOME renders a message inside the
// in-progress notice (ubuntu24arm-/fedora44arm-tier1-18). The OCR'd nonce is
// read as lowercase hex with tesseract's i/l→1 and o→0 confusions folded and
// at most assistanceNonceOCREdits further glyph edits: tesseract doubled
// glyphs of an otherwise clear "…cb001e" as "…cbO001le" (banner-fix-full-01).
// A fresh 96-bit nonce within three edits cannot be matched by chance.
func assistanceMessageVisible(ocr, sender, nonce string) bool {
	normalize := func(value string) string { return strings.Join(strings.Fields(strings.ToLower(value)), " ") }
	text := normalize(ocr)
	if sender == "" || nonce == "" || !strings.Contains(text, "lindm") || !strings.Contains(text, "message from your support operator") {
		return false
	}
	hex := strings.NewReplacer("i", "1", "l", "1", "o", "0")
	isNonce := func(line string) bool {
		token, _, _ := strings.Cut(line, " ")
		return editDistance(hex.Replace(token), strings.ToLower(nonce)) <= assistanceNonceOCREdits
	}
	var lines []string
	for line := range strings.Lines(ocr) {
		if line = normalize(line); line != "" {
			lines = append(lines, line)
		}
	}
	prefix := normalize(sender) + ":"
	for i, line := range lines {
		switch {
		case line == prefix && i+1 < len(lines) && isNonce(lines[i+1]):
			return true
		case strings.HasPrefix(line, prefix+" ") && isNonce(line[len(prefix)+1:]):
			return true
		}
	}
	return false
}

const assistanceNonceOCREdits = 3

// editDistance is the Levenshtein distance between a and b in bytes.
func editDistance(a, b string) int {
	previous := make([]int, len(b)+1)
	for j := range previous {
		previous[j] = j
	}
	for i := 1; i <= len(a); i++ {
		current := make([]int, len(b)+1)
		current[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			current[j] = min(previous[j]+1, current[j-1]+1, previous[j-1]+cost)
		}
		previous = current
	}
	return previous[len(b)]
}
