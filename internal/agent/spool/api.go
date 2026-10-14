// SPDX-License-Identifier: Apache-2.0

// Package spool is the unprivileged network process's durable observation queue.
// It stores no protected identity keys, grants, trust roots or executor journal
// state. The caller opens it as the fixed network UID that owns the directory.
//
// A missing or damaged spool is recoverable only after the current protected
// executor session and a server GetSyncState. Synchronize applies those
// high-water marks. It never recreates protected identity and it cannot reset
// a server upload that was already admitted.
//
// Canceled pending reads do not mark healthy payloads damaged. If ownership
// metadata is unusable, recovery detaches it and waits for Synchronize before
// removing collection directories through validated filesystem cleanup.
package spool

import (
	"errors"
	"time"

	"github.com/google/uuid"

	devicev1 "lindm/gen/lindm/device/v1"
	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

const (
	// SpoolBudget is the physical ceiling for metadata, logs and both
	// collection directories together.
	SpoolBudget = 160 << 20
	// CollectionBudget is the maximum encoded package payload of one
	// collection. One immutable pending collection and one replaceable queued
	// collection may coexist; filesystem block slack counts toward SpoolBudget.
	CollectionBudget = 64 << 20
	// MetadataBudget bounds SQLite, WAL, directory blocks and status files.
	MetadataBudget = 32 << 20

	// LostAdmittedUploadTTL is the server open-upload lifetime fixed at Begin.
	// Retries do not extend it. A payload lost after admission may remain
	// server-open until this duration. This store has no reset authority.
	LostAdmittedUploadTTL = 24 * time.Hour
	// ReceiptTTL is the server compact-receipt lifetime from first acceptance.
	ReceiptTTL = 2160 * time.Hour

	// MaxPackageRecords, MaxBatches, MaxBatchRecords and MaxBatchEncoded match
	// the server snapshot admission bounds. Exceeding them is capacity, not
	// truncation.
	MaxPackageRecords = 100000
	MaxBatches        = 512
	MaxBatchRecords   = 500
	MaxBatchEncoded   = 786432
)

// Identity is the deployment binding copied from the protected executor. The
// spool does not allocate or replace these identifiers.
type Identity struct {
	Deployment uuid.UUID
	Device     uuid.UUID
	Generation uuid.UUID
}

// Reason explains why fresh allocations are refused until Synchronize.
type Reason string

const (
	ReasonNone           Reason = ""
	ReasonUnsynchronized Reason = "unsynchronized"
	ReasonFence          Reason = "session-fence"
	ReasonMissing        Reason = "missing"
	ReasonCorrupt        Reason = "corrupt"
	ReasonScopeChange    Reason = "scope-change"
	ReasonDamagedPending Reason = "damaged-pending"
	ReasonUnrecognized   Reason = "unrecognized-entry"
)

// Recovery is the durable fence state. Counters are meaningful for Identity
// only when NeedsSync is false or Reason is a same-scope damage recovery that
// has not yet been synchronized. On scope change, counters are zero and Stored
// is the previous binding.
type Recovery struct {
	NeedsSync                   bool
	Reason                      Reason
	LostAdmittedUploadMayRemain bool
	Identity                    Identity
	Stored                      Identity
	HostAllocated               uint64
	PackageAllocated            uint64
	HostHighwater               uint64
	PackageHighwater            uint64
}

// HostUpload is one immutable host observation. The RPC epoch is not stored;
// the driver supplies the current executor epoch on the request.
type HostUpload struct {
	Sequence    uint64
	Observation *inventoryv1.HostObservation
}

// PackageUpload is one immutable package attempt. Success with an empty batch
// list is a successful zero-package snapshot, distinct from a failure.
// CanonicalManifest is the deterministic protobuf encoding. ManifestDigest is
// SHA-256 of those bytes. The manifest does not carry session_epoch.
type PackageUpload struct {
	Sequence          uint64
	Success           bool
	Status            inventoryv1.CollectionStatus
	Backend           string
	StartedAt         time.Time
	FinishedAt        time.Time
	Manifest          *devicev1.PackageSnapshotManifest
	CanonicalManifest []byte
	ManifestDigest    [32]byte
	BatchCount        int
	// BeginAccepted records a local MarkBegin. It is not server publication proof.
	BeginAccepted bool
	// AcceptedBatches are indexes durably marked by MarkBatchAccepted, at most
	// 512. Recording a successful Put does not require a local BeginAccepted
	// hint. The driver still Begins every cycle, then skips these Puts while
	// the server reports staging. A COMMITTED receipt requires neither hint.
	AcceptedBatches []uint32
}

// Terminal is how a package attempt ended. Superseded and expired discard the
// local payload without rewinding allocated counters.
type Terminal uint8

const (
	// TerminalAdmitted means the server Commit response was COMMITTED for this
	// exact attempt. serverHigh must be >= seq and seq must match the pending
	// attempt. Local Begin/batch marks are not required: they are retransmission
	// hints, not publication proof. The caller must not use this for a
	// GetSyncState high-water alone.
	TerminalAdmitted Terminal = 1
	// TerminalSuperseded discards an older uncommitted attempt.
	TerminalSuperseded Terminal = 2
	// TerminalExpired discards an attempt the server refused as expired.
	TerminalExpired Terminal = 3
)

var (
	ErrNeedsSync    = errors.New("observation spool requires server sync")
	ErrAlreadyOpen  = errors.New("observation spool already has an owner")
	ErrClosed       = errors.New("observation spool is closed")
	ErrConflict     = errors.New("observation spool sequence conflict")
	ErrPending      = errors.New("observation spool already has an immutable pending upload")
	ErrEmpty        = errors.New("observation spool has no queued observation")
	ErrCapacity     = errors.New("observation exceeds spool budget")
	ErrInvalid      = errors.New("observation spool rejected the observation")
	ErrUnsafe       = errors.New("unsafe observation spool filesystem boundary")
	ErrUnrecognized = errors.New("observation spool directory contains an unrecognized entry")
	ErrNotFound     = errors.New("observation spool batch is absent")
)
