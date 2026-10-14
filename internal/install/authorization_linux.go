// SPDX-License-Identifier: Apache-2.0

//go:build linux

package install

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// A native hook may consume authorization only in this installer's process tree.
// Start time prevents an abandoned token from authorizing a later reused PID.
func packageAuthorization(version string) ([]byte, error) {
	stat, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return nil, err
	}
	_, tail, ok := strings.Cut(string(stat), ") ")
	if !ok {
		return nil, errors.New("cannot bind native transaction to installer process")
	}
	fields := strings.Fields(tail)
	if len(fields) < 20 {
		return nil, errors.New("invalid installer process identity")
	}
	return []byte(fmt.Sprintf("%s\n%d\n%s\n", version, os.Getpid(), fields[19])), nil
}
