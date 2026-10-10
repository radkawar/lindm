package update

import (
	"errors"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

	agentv1 "lindm/gen/lindm/agent/v1"
)

const nativeOutputLimit = 65536
const nativeDiagnosticLines = 8
const nativeDiagnosticLineBytes = 512

// Keep the final output independently of the bounded prefix used to validate
// package-manager replies. A verbose command must not hide its terminal error.
type nativeOutputTail struct {
	data      [nativeOutputLimit]byte
	start     int
	size      int
	truncated bool
	pemMatch  int
	pemSeen   bool
}

func (b *nativeOutputTail) write(p []byte) {
	// Recognize a PEM block before any tail rotation can discard its header.
	// Suppress this stream rather than risk persisting headerless key material.
	const pem = "-----BEGIN "
	if !b.pemSeen {
		for _, c := range p {
			if c == pem[b.pemMatch] {
				b.pemMatch++
				if b.pemMatch == len(pem) {
					b.pemSeen = true
					break
				}
			} else if c != '-' || b.pemMatch != 5 {
				b.pemMatch = 0
				if c == '-' {
					b.pemMatch = 1
				}
			}
		}
	}
	if len(p) >= len(b.data) {
		b.truncated = b.truncated || b.size > 0 || len(p) > len(b.data)
		copy(b.data[:], p[len(p)-len(b.data):])
		b.start, b.size = 0, len(b.data)
		return
	}
	if excess := b.size + len(p) - len(b.data); excess > 0 {
		b.start = (b.start + excess) % len(b.data)
		b.size -= excess
		b.truncated = true
	}
	end := (b.start + b.size) % len(b.data)
	n := copy(b.data[end:], p)
	copy(b.data[:], p[n:])
	b.size += len(p)
}

func (b *nativeOutputTail) text() string {
	if b.pemSeen {
		return "[redacted sensitive native output]"
	}
	var text strings.Builder
	text.Grow(b.size)
	n := min(b.size, len(b.data)-b.start)
	text.Write(b.data[b.start : b.start+n])
	text.Write(b.data[:b.size-n])
	value := text.String()
	if b.truncated {
		// The retained prefix may start inside a credential or escape sequence.
		// Drop that entire partial line, never sanitize a misleading fragment.
		if _, rest, ok := strings.Cut(value, "\n"); ok {
			return rest
		}
		return "[native output line omitted: exceeds bound]"
	}
	return value
}

var nativeURL = regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://[^\s<>"']+|[^\s<>"']*[?@][^\s<>"']*`)
var nativeSensitive = regexp.MustCompile(`(?i)\b(password|passwd|passphrase|secret|token|authorization|proxy-authorization|cookie|credentials?|api[-_]?key|access[-_]?key|private[-_]?key|bearer|basic)\b|[a-z_][a-z0-9_:.-]*\s*=`)

func sanitizeNativeLine(line string) (string, bool) {
	// Consume complete ANSI CSI and string escapes, including OSC hyperlinks.
	// Removing only ESC would expose hidden OSC contents and spoofed text.
	var clean strings.Builder
	clean.Grow(len(line))
	for i := 0; i < len(line); {
		r, n := utf8.DecodeRuneInString(line[i:])
		i += n
		if r == '\x1b' && i < len(line) {
			r = rune(line[i])
			i++
			switch r {
			case '[':
				r = '\u009b'
			case ']', 'P', 'X', '^', '_':
				r = '\u009d'
			default:
				continue
			}
		}
		if r == '\u009b' {
			for i < len(line) {
				c := line[i]
				i++
				if c >= 0x40 && c <= 0x7e {
					break
				}
			}
			continue
		}
		if r == '\u009d' || r == '\u0090' || r == '\u0098' || r == '\u009e' || r == '\u009f' {
			for i < len(line) {
				c, size := utf8.DecodeRuneInString(line[i:])
				i += size
				if c == '\a' || c == '\u009c' {
					break
				}
				if c == '\x1b' && i < len(line) && line[i] == '\\' {
					i++
					break
				}
			}
			continue
		}
		if r == '\t' || r == '\r' {
			clean.WriteByte(' ')
		} else if !unicode.IsControl(r) && !unicode.Is(unicode.Cf, r) && r != utf8.RuneError {
			clean.WriteRune(r)
		}
	}
	value := strings.TrimSpace(clean.String())
	// Never persist assignments/environment dumps or credential-bearing lines.
	// Redact whole URLs too: credentials can live in path segments, not just
	// userinfo and query parameters. No argv, configuration or environment is
	// appended to the child's diagnostic output.
	if nativeSensitive.MatchString(value) {
		value = "[redacted sensitive native output]"
	} else {
		value = nativeURL.ReplaceAllString(value, "[redacted-url]")
	}
	if len(value) <= nativeDiagnosticLineBytes {
		return value, false
	}
	end := nativeDiagnosticLineBytes
	for !utf8.RuneStart(value[end]) {
		end--
	}
	return value[:end], true
}

func commandDiagnostic(program, phase string, err error, stdout, stderr *commandOutput) *agentv1.NativeUpdateDiagnostic {
	diagnostic := &agentv1.NativeUpdateDiagnostic{Manager: program, Phase: phase, ExitCode: -1, Truncated: stdout.overflow || stderr.overflow}
	var exit interface{ ExitCode() int }
	if errors.As(err, &exit) {
		diagnostic.ExitCode = int32(exit.ExitCode())
	}
	// Prefer final stderr when both streams exceed the eight-line envelope;
	// dnf and native verifiers also report actual failures on stdout.
	for _, output := range []*commandOutput{stdout, stderr} {
		for line := range strings.SplitSeq(output.tail.text(), "\n") {
			line, truncated := sanitizeNativeLine(line)
			diagnostic.Truncated = diagnostic.Truncated || truncated
			if line == "" {
				continue
			}
			if len(diagnostic.ErrorLines) == nativeDiagnosticLines {
				copy(diagnostic.ErrorLines, diagnostic.ErrorLines[1:])
				diagnostic.ErrorLines = diagnostic.ErrorLines[:nativeDiagnosticLines-1]
				diagnostic.Truncated = true
			}
			diagnostic.ErrorLines = append(diagnostic.ErrorLines, line)
		}
	}
	return diagnostic
}

func managerExecutable(manager agentv1.NativeUpdateManager) string {
	switch manager {
	case agentv1.NativeUpdateManager_NATIVE_UPDATE_MANAGER_APT:
		return "apt-get"
	case agentv1.NativeUpdateManager_NATIVE_UPDATE_MANAGER_DNF:
		return "dnf"
	case agentv1.NativeUpdateManager_NATIVE_UPDATE_MANAGER_ZYPPER:
		return "zypper"
	case agentv1.NativeUpdateManager_NATIVE_UPDATE_MANAGER_PACMAN:
		return "pacman"
	default:
		return ""
	}
}

func withNativeDiagnostic(err error, manager, phase string) error {
	if err == nil || manager == "" {
		return err
	}
	var failure *nativeFailure
	if errors.As(err, &failure) && failure.diagnostic != nil {
		return err
	}
	return &nativeFailure{program: manager, cause: err, diagnostic: &agentv1.NativeUpdateDiagnostic{Manager: manager, Phase: phase, ExitCode: -1}}
}

func diagnosticForError(err error) *agentv1.NativeUpdateDiagnostic {
	var failure *nativeFailure
	if errors.As(err, &failure) {
		return proto.CloneOf(failure.diagnostic)
	}
	return nil
}
