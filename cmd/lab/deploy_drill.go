// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"

	"lindm/internal/labexec"
)

func validateDeployDrillImage(image string) error {
	if image == "" {
		return nil // Use the operator's matching native client.
	}
	digest, ok := strings.CutPrefix(image, "docker.io/library/postgres@sha256:")
	if !ok || len(digest) != 64 || digest != strings.ToLower(digest) {
		return errors.New("offline drill image must be a digest-pinned official docker.io/library/postgres image")
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return errors.New("offline drill image has an invalid SHA256 digest")
	}
	return nil
}

// This is an off-server operator process, not an online-server backup identity
// transfer. The image is pre-pulled and independently pinned before the lane.
func offlineContainerDrill(ctx context.Context, repository, image, binary, archive, identity string, passphrase []byte) (err error) {
	if image == "" {
		return errors.New("offline container drill requires a pinned image")
	}
	if err := validateDeployDrillImage(image); err != nil {
		return err
	}
	name := "lindm-deploy-drill-" + uuid.NewString()
	args, err := deployDrillContainerArgs(name, image, binary, archive, identity)
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer cancel()
		removeErr := labexec.Run(cleanup, labexec.Command{Path: "docker", Args: []string{"rm", "--force", "--volumes", name}, Dir: repository, Stdout: io.Discard, Stderr: io.Discard, Timeout: 30 * time.Second})
		if removeErr != nil {
			err = errors.Join(err, errors.New("owned offline drill container cleanup failed (protected output withheld)"))
		}
	}()
	if err := labexec.Run(ctx, labexec.Command{Path: "docker", Args: args, Dir: repository, Stdout: io.Discard, Stderr: io.Discard, Timeout: time.Minute}); err != nil {
		return errors.New("create pinned networkless offline drill container failed (protected output withheld)")
	}
	pipe, err := protectedDeployPipe(passphrase)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, pipe.Close()) }()
	if err := labexec.Run(ctx, labexec.Command{Path: "docker", Args: []string{"start", "--attach", "--interactive", name}, Dir: repository, Stdin: pipe, Stdout: io.Discard, Stderr: io.Discard, Timeout: 10 * time.Minute, Interrupt: syscall.SIGTERM, Grace: 30 * time.Second}); err != nil {
		return errors.New("pinned offline restore drill failed (protected output withheld)")
	}
	return nil
}

func deployDrillContainerArgs(name, image, binary, archive, identity string) ([]string, error) {
	args := []string{
		"create", "--name", name, "--interactive", "--pull=never", "--platform=linux/amd64",
		"--network=none", "--read-only", "--log-driver=none", "--cap-drop=ALL", "--security-opt=no-new-privileges",
		"--user", strconv.Itoa(os.Geteuid()) + ":" + strconv.Itoa(os.Getegid()),
		"--memory=2g", "--memory-swap=2g", "--pids-limit=256", "--ulimit=core=0:0", "--ulimit=memlock=-1:-1",
		"--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=1g,mode=1777",
		"--tmpfs=/run:rw,noexec,nosuid,nodev,size=1g,mode=0755",
	}
	for _, mount := range []struct{ source, destination string }{{binary, "/lindmd"}, {archive, "/archive.age"}, {identity, "/identity.age"}} {
		path, err := filepath.Abs(mount.source)
		if err != nil || mount.source == "" || strings.ContainsAny(path, ",\r\n\x00") {
			return nil, errors.New("offline drill requires unambiguous native artifact mount paths")
		}
		args = append(args, "--mount", fmt.Sprintf("type=bind,src=%s,dst=%s,readonly", path, mount.destination))
	}
	// The official image's PGDATA/PG_MAJOR/PG_VERSION environment is not an
	// application database authority. Clear it exactly as native operator tools do.
	args = append(args, "--entrypoint=/usr/bin/env", image, "-i", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/nonexistent", "LANG=C", "LC_ALL=C", "/lindmd", "restore-drill", "-archive", "/archive.age", "-identity-file", "/identity.age", "-identity-passphrase-fd", "0")
	return args, nil
}
