//go:build linux

package vmlab

import (
	"encoding/base64"

	"lindm/internal/packaging"
)

// unattendedSeed is never evidence. These bytes enter only the private NoCloud
// seed of a fresh disposable overlay, never the verified vendor base image.
type unattendedSeed struct {
	root, bundle, token []byte
	approvalRequired    bool
}

const unattendedDirectory = "/run/lindm-enrollment-lab"

func (s *unattendedSeed) apply(config map[string]any) {
	files := make([]any, 0, 3)
	for _, file := range []struct {
		name string
		data []byte
	}{
		{"root.json", s.root}, {"bootstrap.json", s.bundle}, {"token", s.token},
	} {
		files = append(files, map[string]any{"path": unattendedDirectory + "/" + file.name, "owner": "root:root", "permissions": "0600", "encoding": "b64", "content": base64.StdEncoding.EncodeToString(file.data)})
	}
	if s.approvalRequired {
		files = append(files, map[string]any{"path": unattendedDirectory + "/approval-required", "owner": "root:root", "permissions": "0600", "content": "true"})
	}
	config["write_files"] = files
	// No bootstrap RPC is issued over SSH. Cloud-init alone runs the installed
	// agent after native signature verification and isolated port forwarding.
	// Its output is discarded: neither token nor RPC error bodies enter logs.
	commands, _ := config["runcmd"].([]any) // absent or foreign-typed runcmd starts empty.
	config["runcmd"] = append(commands, []string{"sh", "-c", unattendedBootCommand})
}

const unattendedBootCommand = `set -eu
umask 077
cd /run/lindm-enrollment-lab
chmod 0700 .
attempt=0
until test -f ready; do
 attempt=$((attempt + 1)); test "$attempt" -lt 600; sleep 1
done
set +e
` + packaging.BinaryPath + ` bootstrap -root root.json -bundle bootstrap.json -provisioning-token-file token >/dev/null 2>&1
code=$?
set -e
printf '%s\n' "$code" > bootstrap-exit
rm -f token
test "$code" -eq 0
if test -f approval-required; then
 ` + packaging.BinaryPath + ` resume -wait-seconds 600 >/dev/null 2>&1
fi
systemctl restart lindm-agent.service
touch complete
`
