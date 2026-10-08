package spool

import (
	"crypto/sha256"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

// batchPlan is one contiguous group. wires are the deterministic Package
// encodings; the batch file is assembled once from them at write time.
type batchPlan struct {
	records uint32
	size    int
	wires   [][]byte
}

// planBatches groups packages by the 500-record and 768 KiB encoded limits.
// Each package is marshaled once. Lengths use protowire accounting so the
// batch buffer is allocated at its final size. Oversized input is rejected;
// nothing is truncated.
func planBatches(packages []*inventoryv1.Package) ([]batchPlan, int64, error) {
	if len(packages) == 0 {
		return nil, 0, nil
	}
	if len(packages) > MaxPackageRecords {
		return nil, 0, ErrCapacity
	}
	sizes := make([]int, len(packages))
	wires := make([][]byte, len(packages))
	var total int
	for i, pkg := range packages {
		if pkg == nil {
			return nil, 0, ErrInvalid
		}
		wire, err := proto.MarshalOptions{Deterministic: true}.Marshal(pkg)
		if err != nil || len(wire) == 0 {
			return nil, 0, ErrInvalid
		}
		n := 1 + protowire.SizeVarint(uint64(len(wire))) + len(wire)
		if n > MaxBatchEncoded || total > CollectionBudget-n {
			return nil, 0, ErrCapacity
		}
		total += n
		sizes[i] = n
		wires[i] = wire
	}
	var planned []batchPlan
	for start := 0; start < len(wires); {
		if len(planned) == MaxBatches {
			return nil, 0, ErrCapacity
		}
		count := 0
		size := 0
		for start+count < len(wires) && count < MaxBatchRecords && size+sizes[start+count] <= MaxBatchEncoded {
			size += sizes[start+count]
			count++
		}
		if count == 0 {
			return nil, 0, ErrCapacity
		}
		planned = append(planned, batchPlan{
			records: uint32(count),
			size:    size,
			wires:   wires[start : start+count],
		})
		start += count
	}
	return planned, int64(total), nil
}

func assembleBatch(plan batchPlan) ([]byte, [32]byte, error) {
	buf := make([]byte, 0, plan.size)
	for _, wire := range plan.wires {
		buf = protowire.AppendTag(buf, 1, protowire.BytesType)
		buf = protowire.AppendVarint(buf, uint64(len(wire)))
		buf = append(buf, wire...)
	}
	if len(buf) != plan.size || len(buf) == 0 || len(buf) > MaxBatchEncoded {
		return nil, [32]byte{}, ErrInvalid
	}
	decoded := &inventoryv1.PackageBatch{}
	if err := proto.Unmarshal(buf, decoded); err != nil || proto.Size(decoded) != len(buf) || len(decoded.GetPackages()) != int(plan.records) {
		return nil, [32]byte{}, ErrInvalid
	}
	return buf, sha256.Sum256(buf), nil
}
