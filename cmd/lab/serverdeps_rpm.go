// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	serverdepsv1 "lindm/gen/lindm/serverdeps/v1"
	"lindm/internal/serverdeps"
)

const rpmDependenciesGuestRoot = "/var/tmp/lindm-serverdeps-rpm/repository"

// This development-only probe executes the real serverdeps native backend in
// the admitted disposable guest. It has no credential arguments or environment
// and never emits native package-manager or RHSM diagnostics.
func runRPMServerDependenciesGuest(ctx context.Context, operation string, stdout io.Writer) error {
	if os.Geteuid() != 0 {
		return errors.New("RPM server dependency probe requires a disposable root guest")
	}
	ctx, cancel := context.WithTimeout(ctx, 35*time.Minute)
	defer cancel()
	payload, err := io.ReadAll(io.LimitReader(os.Stdin, (8<<20)+1))
	if err != nil || len(payload) == 0 || len(payload) > 8<<20 {
		return errors.New("RPM server dependency input exceeds bounded manifest")
	}
	manifest := new(serverdepsv1.Manifest)
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(payload, manifest); err != nil {
		return errors.New("invalid RPM server dependency manifest")
	}
	var result *serverdepsv1.Manifest
	switch operation {
	case "serverdeps-rpm-capture":
		if err := os.Mkdir("/var/tmp/lindm-serverdeps-rpm", 0700); err != nil {
			return err
		}
		if err := os.Mkdir(rpmDependenciesGuestRoot, 0700); err != nil {
			return err
		}
		result, err = serverdeps.CaptureRPM(ctx, rpmDependenciesGuestRoot, manifest)
	case "serverdeps-rpm-replay":
		result, err = serverdeps.ReplayRPM(ctx, rpmDependenciesGuestRoot, manifest)
	default:
		return errors.New("unknown RPM server dependency operation")
	}
	if err != nil {
		return err
	}
	encoded, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(result)
	if err != nil {
		return err
	}
	_, err = stdout.Write(encoded)
	return err
}
