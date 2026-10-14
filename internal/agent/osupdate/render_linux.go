// SPDX-License-Identifier: Apache-2.0

//go:build linux

package osupdate

import (
	"errors"
	"slices"
	"strings"

	resourcev1 "lindm/gen/lindm/resource/v1"
)

// maxExcludeArg keeps each `--exclude=` argument well below the kernel's
// MAX_ARG_STRLEN (128 KiB) for a single argv string.
const maxExcludeArg = 32 << 10

var errDNF5AutomaticConfig = errors.New("dnf5_automatic_config_mismatch")

// renderAPTConfig is the APT_CONFIG file. APT reads it first, then
// Dir::Etc::parts (apt.conf.d), then Dir::Etc::main last
// (apt-pkg/init.cc pkgInitConfig), so pointing main at the per-run file
// makes its #clear and assignments win over the system's
// 50unattended-upgrades. unattended-upgrade uses apt_pkg.init_config, which
// takes the same path.
func renderAPTConfig(mainPath string) []byte {
	return []byte("// lindm os-update per-run APT configuration.\nDir::Etc::main \"" + mainPath + "\";\n")
}

// renderAPTMain is the per-run main file. It still includes the system
// /etc/apt/apt.conf that it replaces as Dir::Etc::main. The origin list is
// cleared and re-declared from the selection. ${distro_id} and
// ${distro_codename} are expanded by unattended-upgrade itself. Deferred
// packages are appended to Package-Blacklist (which stays non-cleared, so the
// administrator's blacklist still applies) as anchored regular expressions;
// `[.]` and `[+]` avoid backslash escapes, which APT's parser does not
// define. The blacklist matches names on every architecture.
func renderAPTMain(selection resourcev1.UpdateSelection, includeSystemMain bool, deferred []packageKey) []byte {
	var b strings.Builder
	b.WriteString("// lindm os-update per-run unattended-upgrade policy.\n")
	if includeSystemMain {
		b.WriteString("#include \"/etc/apt/apt.conf\";\n")
	}
	b.WriteString("#clear Unattended-Upgrade::Allowed-Origins;\n#clear Unattended-Upgrade::Origins-Pattern;\nUnattended-Upgrade::Allowed-Origins {\n")
	origins := []string{"${distro_id}:${distro_codename}-security", "${distro_id}ESMApps:${distro_codename}-apps-security", "${distro_id}ESM:${distro_codename}-infra-security"}
	if selection == resourcev1.UpdateSelection_UPDATE_SELECTION_ALL {
		origins = append(origins, "${distro_id}:${distro_codename}-updates", "${distro_id}:${distro_codename}")
	}
	for _, origin := range origins {
		b.WriteString("\t\"" + origin + "\";\n")
	}
	b.WriteString("};\n")
	names := make([]string, 0, len(deferred))
	for _, key := range deferred {
		names = append(names, key.name)
	}
	slices.Sort(names)
	names = slices.Compact(names)
	if len(names) != 0 {
		b.WriteString("Unattended-Upgrade::Package-Blacklist {\n")
		for _, name := range names {
			b.WriteString("\t\"^" + aptRegexpLiteral(name) + "$\";\n")
		}
		b.WriteString("};\n")
	}
	b.WriteString("Unattended-Upgrade::Automatic-Reboot \"false\";\nUnattended-Upgrade::MinimalSteps \"true\";\n")
	return []byte(b.String())
}

// aptRegexpLiteral quotes the only regexp metacharacters valid in Debian
// package names (validated against packageNamePattern before rendering).
func aptRegexpLiteral(name string) string {
	return strings.NewReplacer(".", "[.]", "+", "[+]").Replace(name)
}

// renderDNFAutomatic is the dnf-automatic (DNF 4) per-run configuration,
// passed as its positional conf_path (dnf/automatic/main.py 4.14:
// AutomaticConfig(opts.conf_path)). [base] is populated at
// PRIO_AUTOMATICCONFIG and excludepkgs is an append option (libdnf
// optionTListAppend), so these excludes extend dnf.conf's. The option is
// omitted when empty because an empty value clears the list. dnf 4.14
// ignores the unknown `reboot` key (debug log only); newer dnf-automatic
// honors it.
func renderDNFAutomatic(selection resourcev1.UpdateSelection, deferred []packageKey) []byte {
	var b strings.Builder
	b.WriteString("# lindm os-update per-run dnf-automatic configuration.\n[commands]\n")
	b.WriteString("upgrade_type = " + dnfUpgradeType(selection) + "\n")
	b.WriteString("random_sleep = 0\nnetwork_online_timeout = 60\ndownload_updates = yes\napply_updates = yes\nreboot = never\n")
	b.WriteString("[emitters]\nemit_via = stdio\n")
	b.WriteString("[base]\n")
	if specs := dnfExcludeSpecs(deferred); len(specs) != 0 {
		b.WriteString("excludepkgs = " + strings.Join(specs, ",") + "\n")
	}
	return []byte(b.String())
}

func dnfUpgradeType(selection resourcev1.UpdateSelection) string {
	if selection == resourcev1.UpdateSelection_UPDATE_SELECTION_ALL {
		return "default"
	}
	return "security"
}

func dnfExcludeSpecs(deferred []packageKey) []string {
	specs := make([]string, 0, len(deferred))
	for _, key := range deferred {
		specs = append(specs, key.name+"."+key.arch)
	}
	return specs
}

// dnf5ExcludeArgs renders the global `--exclude=` options. dnf5 appends each
// one to excludepkgs at COMMANDLINE priority (dnf5/main.cpp), and the sack
// excludes reach the automatic and upgrade goals. Several arguments keep
// each below MAX_ARG_STRLEN; none is ever empty, because that would clear
// the configured excludes.
func dnf5ExcludeArgs(deferred []packageKey) []string {
	var args []string
	var current []string
	size := 0
	for _, spec := range dnfExcludeSpecs(deferred) {
		if size+len(spec)+1 > maxExcludeArg && len(current) != 0 {
			args = append(args, "--exclude="+strings.Join(current, ","))
			current, size = nil, 0
		}
		current = append(current, spec)
		size += len(spec) + 1
	}
	if len(current) != 0 {
		args = append(args, "--exclude="+strings.Join(current, ","))
	}
	return args
}

// dnf5AutomaticSettings is the effective subset of `dnf5 automatic`
// configuration that decides what a window run does.
type dnf5AutomaticSettings struct {
	upgradeType, reboot string
	emitVia             []string
}

// effectiveDNF5Automatic folds the configuration files in the order dnf5
// automatic reads them (AutomaticCommand::pre_configure). Each file is
// loaded at the same priority, so a later file wins per key. Absent files are
// nil. Defaults are the plugin's compiled ones.
func effectiveDNF5Automatic(files ...[]byte) dnf5AutomaticSettings {
	settings := dnf5AutomaticSettings{upgradeType: "default", reboot: "never", emitVia: []string{"stdio"}}
	for _, data := range files {
		section := ""
		for line := range strings.SplitSeq(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || line[0] == '#' || line[0] == ';' {
				continue
			}
			if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
				section = strings.TrimSpace(line[1 : len(line)-1])
				continue
			}
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			key, value = strings.TrimSpace(key), strings.TrimSpace(value)
			switch section + "." + key {
			case "commands.upgrade_type":
				settings.upgradeType = value
			case "commands.reboot":
				settings.reboot = value
			case "emitters.emit_via":
				settings.emitVia = strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
			}
		}
	}
	return settings
}

// checkDNF5Automatic requires the effective configuration to install exactly
// the selection, never reboot on its own (reboots are lindm's logind
// schedule) and report only locally (no command or mail emitters).
func checkDNF5Automatic(settings dnf5AutomaticSettings, selection resourcev1.UpdateSelection) error {
	if settings.upgradeType != dnfUpgradeType(selection) || settings.reboot != "never" {
		return errDNF5AutomaticConfig
	}
	for _, emitter := range settings.emitVia {
		if emitter != "stdio" && emitter != "motd" {
			return errDNF5AutomaticConfig
		}
	}
	return nil
}
