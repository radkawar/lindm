package device

import (
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// Paged responses have bounded envelopes: field names, snapshot identity,
// sequence/expiry and fixed-length cursor tokens. Reserve ample envelope space
// in either Connect encoding, independently of the requested page size.
// Admitted string capacities are not reduced.
const pageEnvelopeBytes = 1024

type responsePageBudget struct {
	used int
	json []byte
}

// take accounts for one device, package or profile summary in protobuf and Connect
// JSON. Marshal only this row, reusing the buffer, rather than repeatedly
// serializing the growing page. Pretty JSON conservatively accounts for escaping
// and optional whitespace at every nesting depth, including typed metadata maps.
// Repeated protobuf field tags are one byte followed by a length-delimited row.
func (b *responsePageBudget) take(row proto.Message) (bool, error) {
	var err error
	b.json, err = (protojson.MarshalOptions{Multiline: true, Indent: " "}).MarshalAppend(b.json[:0], row)
	if err != nil {
		return false, err
	}
	binaryBytes := 1 + protowire.SizeBytes(proto.Size(row))
	jsonBytes := len(b.json) + 2
	encodedBytes := max(binaryBytes, jsonBytes)
	if encodedBytes > maxMessageBytes-pageEnvelopeBytes-b.used {
		return false, nil
	}
	b.used += encodedBytes
	return true, nil
}
