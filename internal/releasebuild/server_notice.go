// SPDX-License-Identifier: Apache-2.0

//go:build linux

package releasebuild

import (
	"errors"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"

	releasev1 "lindm/gen/lindm/release/v1"
)

// LoadServerNotice reads an explicitly supplied operator bulletin for inclusion
// inside the signed ReleaseManifest. There is no unsigned runtime notice source.
func LoadServerNotice(path string) (*releasev1.ServerReleaseNotice, error) {
	data, err := readProtected(path, 16<<10)
	if err != nil {
		return nil, err
	}
	notice := new(releasev1.ServerReleaseNotice)
	if err = protojson.Unmarshal(data, notice); err != nil {
		return nil, errors.New("releasebuild: invalid server release notice")
	}
	if err = protovalidate.Validate(notice); err != nil {
		return nil, errors.New("releasebuild: invalid server release notice")
	}
	return notice, nil
}
