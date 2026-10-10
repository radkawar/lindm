//go:build linux

package actionprovider

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func deviceNumber(value string) bool {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, digit := range part {
			if digit < '0' || digit > '9' {
				return false
			}
		}
		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			return false
		}
	}
	return true
}

// rootMapping freezes the real mounted-root dependency graph, kernel dm UUIDs
// and redacted crypt tables. No keys are requested from device mapper. Only the
// backing device of the single root LUKS2 mapping qualifies; a LUKS volume merely
// sharing the root's disk does not. LVM above that mapping is supported.
func (p *Provider) rootMapping(ctx context.Context, targets []*targetHandle) (int, []byte, error) {
	var root unix.Stat_t
	if err := unix.Stat("/", &root); err != nil {
		return -1, nil, err
	}
	rootDevice := fmt.Sprintf("%d:%d", unix.Major(root.Dev), unix.Minor(root.Dev))
	seen := make(map[string]bool)
	var facts []string
	var cryptIDs []string
	var visit func(string) error
	visit = func(device string) error {
		if !deviceNumber(device) || seen[device] {
			return ErrConflict
		}
		seen[device] = true
		base := "/sys/dev/block/" + device
		uuid, err := os.ReadFile(base + "/dm/uuid")
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		id := strings.TrimSpace(string(uuid))
		facts = append(facts, device+"="+id)
		if strings.HasPrefix(id, "CRYPT-") {
			cryptIDs = append(cryptIDs, id)
		}
		children, err := os.ReadDir(base + "/slaves")
		if os.IsNotExist(err) && id == "" {
			return nil
		}
		if err != nil {
			return err
		}
		for _, child := range children {
			value, err := os.ReadFile(base + "/slaves/" + child.Name() + "/dev")
			if err != nil {
				return err
			}
			next := strings.TrimSpace(string(value))
			facts = append(facts, device+">"+next)
			if err := visit(next); err != nil {
				return err
			}
		}
		return nil
	}
	if err := visit(rootDevice); err != nil {
		return -1, nil, err
	}
	rootIndex, err := matchRootBacking(targets, seen, cryptIDs)
	if err != nil {
		return -1, nil, err
	}
	// The fixed helper's default output masks key material. Hash it in memory;
	// never put native table text in the plan, logs or public diagnostics.
	table, err := p.run(ctx, nativeRequest{command: dmsetup, args: []string{"table", "--target", "crypt"}})
	if err != nil || len(table) == 0 {
		return -1, nil, ErrConflict
	}
	defer clear(table)
	facts = append(facts, strings.Split(strings.TrimSpace(string(table)), "\n")...)
	sort.Strings(facts)
	digest := sha256.Sum256([]byte(strings.Join(facts, "\n")))
	return rootIndex, digest[:], nil
}

func matchRootBacking(targets []*targetHandle, ancestors map[string]bool, cryptIDs []string) (int, error) {
	if len(cryptIDs) != 1 {
		return -1, ErrUnsupported
	}
	rootIndex := -1
	for index, target := range targets {
		if !ancestors[target.node.Device] {
			continue
		}
		prefix := "CRYPT-LUKS2-" + strings.ReplaceAll(target.qualification.GetTarget().GetLuksUuid(), "-", "") + "-"
		if rootIndex >= 0 || !strings.HasPrefix(cryptIDs[0], prefix) {
			return -1, ErrConflict
		}
		rootIndex = index
	}
	if rootIndex < 0 {
		return -1, ErrUnsupported
	}
	return rootIndex, nil
}
