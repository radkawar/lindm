// SPDX-License-Identifier: Apache-2.0

//go:build linux

package serviceprovider

import (
	"fmt"
	"strings"
)

// Charges include retained byte payload and conservative container/entry
// overhead. This bounds graph work, not the runtime's exact resident set.
const (
	snapshotNodeCharge = 512
	snapshotWorkCharge = 64
	snapshotWalkCharge = 128
)

type snapshotWork struct {
	path  string
	class pathClass
}

type symlinkWalkState struct {
	path       string
	suffix     string
	components int
}

func (s *session) reserveMetadata(size int) error {
	if size < 0 || size > maxSnapshotMetadataBytes-s.metadataUsed {
		return fmt.Errorf("%w: snapshot metadata budget exceeded", ErrUnsupported)
	}
	s.metadataUsed += size
	return nil
}

func (s *session) reservePending(size int) error {
	if s.pendingEntries >= maxSnapshotEntries {
		return fmt.Errorf("%w: snapshot pending work exceeds entry limit", ErrUnsupported)
	}
	if err := s.reserveMetadata(snapshotWorkCharge + size); err != nil {
		return err
	}
	s.pendingEntries++
	return nil
}

func (s *session) releasePending(path string) {
	s.pendingEntries--
	s.metadataUsed -= snapshotWorkCharge + len(path)
}

func (s *session) enqueueTarget(path string, class pathClass) error {
	if err := s.reservePending(len(path)); err != nil {
		return err
	}
	s.targets = append(s.targets, snapshotWork{path: path, class: class})
	return nil
}

// Directory symlink targets are processed only after the current walk releases
// its descriptor stack. A shallow chain cannot accumulate nested root walks.
func (s *session) captureTargets() error {
	for len(s.targets) > 0 {
		last := len(s.targets) - 1
		work := s.targets[last]
		s.targets[last] = snapshotWork{}
		s.targets = s.targets[:last]
		err := s.followRecorded(work.path, work.class)
		s.releasePending(work.path)
		if err != nil {
			return err
		}
	}
	return nil
}

// Repeated symlink identity is not a cycle when the remaining suffix changes.
// Reserve before materializing the exact suffix, rather than retaining an
// unbounded set of expanded path strings or relying on a hash collision test.
func (s *session) rememberSymlink(seen map[symlinkWalkState]struct{}, path string, pending []string) (bool, int, error) {
	size := snapshotWalkCharge + len(path)
	for i, component := range pending {
		if i > 0 {
			size++
		}
		size += len(component)
	}
	if err := s.reserveMetadata(size); err != nil {
		return false, 0, err
	}
	// Joining zero components and one empty component produces the same text;
	// the latter still requires a directory, so retain the component count.
	state := symlinkWalkState{path: path, suffix: strings.Join(pending, "/"), components: len(pending)}
	if _, exists := seen[state]; exists {
		s.metadataUsed -= size
		return true, 0, nil
	}
	seen[state] = struct{}{}
	return false, size, nil
}
