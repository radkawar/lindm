// SPDX-License-Identifier: Apache-2.0

package labhost

import (
	"fmt"
	"path/filepath"
)

// assistanceBrowser installs only user-owned tools. The Node archives are pinned
// to the repository toolchain and upstream SHASUMS256.txt; npm ci enforces the
// checked-in package lock, and that Playwright version selects Chromium.
// No system package installation or global environment changes are permitted.
func (s *remoteStage) assistanceBrowser(work, architecture string) (string, error) {
	arch, digest := "", ""
	switch architecture {
	case "arm64":
		arch, digest = "arm64", "6ad1325edbdb5649c379b75a237147a666c95d4f9ae8d340fef2d1575d289ad2"
	case "amd64":
		arch, digest = "x64", "fd8e59d5a511510f6a298afb548f18c7d2b1be404d8b4a27d94fbe49f56cb2d6"
	default:
		return "", fmt.Errorf("assistance browser has no pinned Node archive for %s", architecture)
	}
	name := "node-v24.21.0-linux-" + arch
	tools := filepath.Join(work, "assistance-browser")
	node := filepath.Join(tools, name)
	browserEnv := "export PATH=" + QuoteShell(node+"/bin") + ":\"$PATH\"\nexport PLAYWRIGHT_BROWSERS_PATH=" + QuoteShell(filepath.Join(tools, "chromium"))
	script := "set -euo pipefail\numask 077\nmkdir -p -- " + QuoteShell(tools) + "\nexec 9>" + QuoteShell(filepath.Join(tools, ".install.lock")) + "\nflock 9\n" +
		"if ! test -x " + QuoteShell(node+"/bin/node") + "; then\n" +
		"curl --fail --location --proto '=https' --tlsv1.2 --output " + QuoteShell(filepath.Join(s.remote, name+".tar.xz")) + " " + QuoteShell("https://nodejs.org/dist/v24.21.0/"+name+".tar.xz") + "\n" +
		"printf '%s  %s\\n' " + QuoteShell(digest) + " " + QuoteShell(filepath.Join(s.remote, name+".tar.xz")) + " | sha256sum --check --strict\n" +
		"tar -xJf " + QuoteShell(filepath.Join(s.remote, name+".tar.xz")) + " -C " + QuoteShell(s.remote) + "\nmv -- " + QuoteShell(filepath.Join(s.remote, name)) + " " + QuoteShell(node) + "\nfi\n" + browserEnv + "\n" +
		"cd " + QuoteShell(s.remote+"/source") + "\nnpm ci --ignore-scripts --no-audit --no-fund\nnode node_modules/playwright/cli.js install chromium\n" +
		"chrome=$(node --input-type=module -e 'import {chromium} from \"playwright\"; console.log(chromium.executablePath())')\nldd \"$chrome\"\n" +
		"node --input-type=module -e 'import {chromium} from \"playwright\"; const browser = await chromium.launch({headless:true}); console.log(await browser.version()); await browser.close()'"
	cmd := executionCommand(s.ctx, s.alias, script)
	cmd.Stdout, cmd.Stderr = s.stderr, s.stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("prepare private assistance browser (system libraries must already exist): %w", err)
	}
	return browserEnv, nil
}
