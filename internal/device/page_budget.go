package device

import (
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// Both inventory responses have a bounded envelope: field names, a snapshot
// UUID, sequence, expiry, and at most two fixed-length cursor tokens. Reserve
// ample space for that envelope in either Connect encoding, independently of
// the requested page size. Admitted string capacities are not reduced.
const inventoryPageEnvelopeBytes = 1024

type inventoryPageBudget struct {
	used int
	json []byte
}

// take accounts for one Device or DevicePackage in both protobuf and Connect
// JSON. Marshal only this row, reusing the buffer, rather than repeatedly
// serializing the growing page. JSON escaping can cost more than UTF-8 or
// protobuf size. These rows have scalar fields (including JSON timestamps);
// allow an extra space per field plus the array separator for protojson's
// deliberately unstable comma whitespace. Their repeated protobuf field tags
// are each one byte, followed by a length-delimited row.
func (b *inventoryPageBudget) take(row proto.Message) (bool, error) {
	var err error
	b.json, err = (protojson.MarshalOptions{}).MarshalAppend(b.json[:0], row)
	if err != nil {
		return false, err
	}
	binaryBytes := 1 + protowire.SizeBytes(proto.Size(row))
	jsonBytes := len(b.json) + row.ProtoReflect().Descriptor().Fields().Len() + 2
	encodedBytes := max(binaryBytes, jsonBytes)
	if encodedBytes > maxMessageBytes-inventoryPageEnvelopeBytes-b.used {
		return false, nil
	}
	b.used += encodedBytes
	return true, nil
}
