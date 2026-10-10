package loadlab

import (
	"errors"
	"fmt"
	"io"
	"os"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"

	inventoryv1 "lindm/gen/lindm/inventory/v1"
)

const maxHistoricalHostBytes = 1 << 20

func readHistoricalHost(path string) (_ *inventoryv1.HostObservation, resultErr error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open historical host observation: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect historical host observation: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxHistoricalHostBytes {
		return nil, errors.New("historical host observation must be a nonempty regular file of at most 1 MiB")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxHistoricalHostBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read historical host observation: %w", err)
	}
	if len(data) > maxHistoricalHostBytes {
		return nil, errors.New("historical host observation exceeds 1 MiB")
	}
	host := new(inventoryv1.HostObservation)
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(data, host); err != nil {
		return nil, fmt.Errorf("decode historical HostObservation protobuf JSON: %w", err)
	}
	if err := protovalidate.Validate(host); err != nil {
		return nil, fmt.Errorf("validate historical host observation: %w", err)
	}
	return host, nil
}
