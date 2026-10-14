// SPDX-License-Identifier: Apache-2.0

//go:build linux

package packageprovider

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"

	"lindm/internal/custody"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
	resourcev1 "lindm/gen/lindm/resource/v1"
	"lindm/internal/agent/journal"
	"lindm/internal/resource"
)

func bindPreparationBaseline(directory string, observation *resourcev1.ResourceObservation, ledger *agentv1.ResourceOwnershipLedger) error {
	ownershipDigest, err := journal.ResourceOwnershipDigest(ledger)
	if err != nil {
		return err
	}
	path := filepath.Join(directory, "preparation-before.pb")
	data, err := custody.ReadRoot(path, 128<<10, false)
	if errors.Is(err, os.ErrNotExist) {
		if err := reserveSpace(directory, 2<<20); err != nil {
			return err
		}
		snapshot := &agentv1.ResourceOwnershipSnapshot{Observation: observation}
		data, err := (proto.MarshalOptions{Deterministic: true}).Marshal(snapshot)
		if err != nil {
			return err
		}
		if len(data) > 128<<10 {
			return errors.New("packageprovider: undo baseline capacity")
		}
		if err := atomicFile(filepath.Join(directory, "preparation-ownership.sha256"), ownershipDigest[:], 0600); err != nil {
			return err
		}
		return atomicFile(path, data, 0600)
	}
	if err != nil {
		return err
	}
	snapshot := new(agentv1.ResourceOwnershipSnapshot)
	if err := proto.Unmarshal(data, snapshot); err != nil {
		return err
	}
	if err := resource.ValidateObservation(snapshot.GetObservation()); err != nil {
		return err
	}
	if !proto.Equal(snapshot.GetObservation().GetNativePackage(), observation.GetNativePackage()) {
		return errors.New("packageprovider: native state changed during preparation")
	}
	if snapshot.GetObservation().GetMetadata().GetBootId() != observation.GetMetadata().GetBootId() || !proto.Equal(snapshot.GetObservation().GetMetadata().GetBackend(), observation.GetMetadata().GetBackend()) {
		return errors.New("packageprovider: boot or native backend changed during preparation")
	}
	digest, err := custody.ReadRoot(filepath.Join(directory, "preparation-ownership.sha256"), 32, false)
	if err != nil {
		return err
	}
	if !bytes.Equal(digest, ownershipDigest[:]) {
		return errors.New("packageprovider: ownership changed during preparation")
	}
	return nil
}

// PreparationStats reports exact verified package transfer bytes separately from
// the total current staging footprint (metadata and cache copies included).
// It does not claim a filesystem quota or that package bytes equal disk usage.
func PreparationStats(directory string) (declared, observed uint64, err error) {
	manifest, err := readPreparedManifest(directory)
	if err != nil {
		return 0, 0, err
	}
	for _, entry := range manifest.GetEntries() {
		size := entry.GetArtifact().GetSizeBytes()
		if size > 512<<20 || declared > (512<<20)-size {
			return 0, 0, errors.New("packageprovider: declared staging capacity")
		}
		declared += size
	}
	observed, err = stagingUsage(directory)
	return declared, observed, err
}
