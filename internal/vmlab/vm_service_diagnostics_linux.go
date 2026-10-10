//go:build linux

package vmlab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

// ServiceExecutionStatus is the public journal projection, not retained authority.
// Keeping it in the error preserves observations which cleanup otherwise destroys.
type vmServiceStatusFailure struct {
	status  *agentv1.ServiceExecutionStatus
	started bool
}

func (e *vmServiceStatusFailure) Error() string {
	encoded, err := protojson.MarshalOptions{EmitUnpopulated: true}.Marshal(e.status)
	if err != nil {
		return fmt.Sprintf("signed service execution status serialization failed: %v", err)
	}
	return fmt.Sprintf("signed service execution did not retain verified success with expected start evidence (expected_started=%t): %s", e.started, encoded)
}

func serviceFailureWithJournal(ctx context.Context, vm *guestVM, failure error) error {
	var statusFailure *vmServiceStatusFailure
	if !errors.As(failure, &statusFailure) {
		return failure
	}
	action := statusFailure.status.GetActionId()
	if parsed, err := uuid.Parse(action); err != nil || parsed.String() != action {
		return errors.Join(failure, errors.New("cannot collect service journal without canonical action UUID"))
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	result, err := vm.runResult(ctx, "sudo -n journalctl --no-pager -o json -n 64 -u lindm-executor.service -u lindm-agent.service --grep="+nativeQuote(action), nil, 64<<10, 10*time.Second)
	if err != nil {
		return errors.Join(failure, fmt.Errorf("collect action-scoped service journal: %w", err))
	}
	// journalctl returns 1 when no matching records exist. This is explicit
	// absence, not proof that the action ran or that a failed command succeeded.
	if result.ExitCode != 0 && (result.ExitCode != 1 || len(result.Stdout) != 0) {
		return errors.Join(failure, fmt.Errorf("collect action-scoped service journal: exit %d", result.ExitCode))
	}
	tail, err := serviceJournalProjection(result.Stdout, action)
	if err != nil {
		return errors.Join(failure, err)
	}
	return fmt.Errorf("%w; action-scoped agent/executor journal tail=%s", failure, tail)
}

// Omit free-form messages, environment, credentials and executable arguments.
// Only fixed reason classifications and numeric metadata leave the private guest.
func serviceJournalProjection(data []byte, action string) ([]byte, error) {
	entries := make([]map[string]string, 0)
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var record map[string]json.RawMessage
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			return nil, errors.New("invalid action-scoped service journal JSON")
		}
		entry := make(map[string]string)
		for _, field := range []string{"__REALTIME_TIMESTAMP", "_SYSTEMD_UNIT", "PRIORITY", "MESSAGE"} {
			if raw, ok := record[field]; ok {
				var value string
				if err := json.Unmarshal(raw, &value); err != nil {
					return nil, errors.New("non-text action-scoped service journal field")
				}
				entry[field] = value
			}
		}
		if entry["_SYSTEMD_UNIT"] != "lindm-executor.service" && entry["_SYSTEMD_UNIT"] != "lindm-agent.service" {
			continue
		}
		if !strings.Contains(entry["MESSAGE"], action) {
			continue
		}
		for _, field := range []string{"__REALTIME_TIMESTAMP", "PRIORITY"} {
			if value, exists := entry[field]; exists {
				number, err := strconv.ParseUint(value, 10, 64)
				if err != nil || strconv.FormatUint(number, 10) != value || (field == "PRIORITY" && number > 7) {
					return nil, errors.New("invalid numeric action-scoped service journal field")
				}
			}
		}
		message := strings.ToLower(entry["MESSAGE"])
		reasons := make([]string, 0)
		for _, reason := range []string{"service_result_conflict", "deadline_exceeded", "context deadline exceeded", "permission_denied", "outcome_unknown", "interrupted", "agent_release_unsupported"} {
			if strings.Contains(message, reason) {
				reasons = append(reasons, reason)
			}
		}
		delete(entry, "MESSAGE")
		entry["message_classification"] = strings.Join(reasons, ",")
		entry["message_content"] = "withheld"
		entries = append(entries, entry)
	}
	return json.Marshal(entries)
}

func newServiceStatusFailure(status *agentv1.ServiceExecutionStatus, started bool) error {
	return &vmServiceStatusFailure{status: proto.CloneOf(status), started: started}
}
