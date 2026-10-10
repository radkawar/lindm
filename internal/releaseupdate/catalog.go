package releaseupdate

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strconv"
	"strings"
	"time"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/encoding/protojson"

	updatev1 "lindm/gen/lindm/update/v1"
)

// ParseVersion parses the numeric release identity shared by update and compatibility policy.
func ParseVersion(value string) ([3]uint64, error) {
	var result [3]uint64
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return result, errors.New("releaseupdate: invalid release version")
	}
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil || len(p) > 9 || strconv.FormatUint(n, 10) != p {
			return result, errors.New("releaseupdate: invalid release version")
		}
		result[i] = n
	}
	return result, nil
}
func compareVersion(a, b string) (int, error) {
	x, err := ParseVersion(a)
	if err != nil {
		return 0, err
	}
	y, err := ParseVersion(b)
	if err != nil {
		return 0, err
	}
	for i := range x {
		if x[i] < y[i] {
			return -1, nil
		}
		if x[i] > y[i] {
			return 1, nil
		}
	}
	return 0, nil
}

func validateChannel(validator protovalidate.Validator, channel *updatev1.AgentUpdateChannel, now time.Time) error {
	if channel == nil {
		return errors.New("releaseupdate: missing channel")
	}
	if err := validator.Validate(channel); err != nil {
		return err
	}
	if now.Before(channel.GetIssuedAt().AsTime()) || !now.Before(channel.GetExpiresAt().AsTime()) {
		return errors.New("releaseupdate: channel not currently valid")
	}
	seen := make(map[string]bool, len(channel.GetArtifacts()))
	for _, a := range channel.GetArtifacts() {
		if !safePath(a.GetTargetPath()) {
			return errors.New("releaseupdate: unsafe target path")
		}
		if a.GetSignatureTargetPath() != "" && !safeTargetPath(a.GetSignatureTargetPath()) {
			return errors.New("releaseupdate: unsafe signature target path")
		}
		cmp, err := compareVersion(a.GetMinimumAgentVersion(), a.GetMaximumAgentVersion())
		if err != nil || cmp > 0 {
			return errors.New("releaseupdate: unordered compatibility window")
		}
		key := a.GetArchitecture() + "/" + a.GetPackageFormat() + "/" + a.GetVersion()
		if seen[key] {
			return errors.New("releaseupdate: ambiguous release selection")
		}
		seen[key] = true
	}
	return nil
}

func decodeChannel(validator protovalidate.Validator, data []byte, now time.Time) (*updatev1.AgentUpdateChannel, error) {
	if int64(len(data)) > MaxCatalogBytes {
		return nil, errors.New("releaseupdate: catalog too large")
	}
	channel := new(updatev1.AgentUpdateChannel)
	if err := protojson.Unmarshal(data, channel); err != nil {
		return nil, err
	}
	if err := validateChannel(validator, channel, now); err != nil {
		return nil, err
	}
	return channel, nil
}

func eligible(device, ring string, percentage uint32) bool {
	hash := sha256.Sum256([]byte("lindm-agent-update\x00" + ring + "\x00" + device))
	return binary.BigEndian.Uint64(hash[:8])%100 < uint64(percentage)
}
