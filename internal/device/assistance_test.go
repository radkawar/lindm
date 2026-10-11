package device

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"unicode/utf8"
)

const (
	testFingerprint = "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89"
	testRelayIP     = "192.0.2.10"
)

// testAssistanceSDP is a complete non-trickle relay-only offer shaped like the
// helper's and browsers' output: one fingerprint line per media section.
func testAssistanceSDP(fingerprints []string, candidates ...string) string {
	lines := []string{"v=0", "o=- 1 2 IN IP4 0.0.0.0", "s=-", "t=0 0", "a=group:BUNDLE 0 1"}
	lines = append(lines, "m=video 9 UDP/TLS/RTP/SAVPF 96", "c=IN IP4 0.0.0.0")
	for i, fingerprint := range fingerprints {
		if i == 1 {
			lines = append(lines, "m=application 9 UDP/DTLS/SCTP webrtc-datachannel")
		}
		lines = append(lines, "a=fingerprint:"+fingerprint)
	}
	for _, candidate := range candidates {
		lines = append(lines, "a=candidate:"+candidate)
	}
	return strings.Join(lines, "\r\n") + "\r\n"
}

func TestAssistanceSDPRequiresOneFingerprintAndRelayCandidates(t *testing.T) {
	relay := netip.MustParseAddr(testRelayIP)
	relayCandidate := "1 1 udp 16777215 " + testRelayIP + " 21000 typ relay raddr 0.0.0.0 rport 0"
	got, err := assistanceSDP(testAssistanceSDP([]string{"sha-256 " + strings.ToLower(testFingerprint), "SHA-256 " + testFingerprint}, relayCandidate), relay)
	if err != nil || got != "sha-256 "+testFingerprint {
		t.Fatalf("valid relay-only offer: %q %v", got, err)
	}
	other := strings.Replace(testFingerprint, "AB", "00", 1)
	for name, test := range map[string]struct {
		sdp  string
		want error
	}{
		"no fingerprint":       {testAssistanceSDP(nil, relayCandidate), errAssistanceFingerprint},
		"two fingerprints":     {testAssistanceSDP([]string{"sha-256 " + testFingerprint, "sha-256 " + other}, relayCandidate), errAssistanceFingerprint},
		"sha-1":                {testAssistanceSDP([]string{"sha-1 " + testFingerprint[:59]}, relayCandidate), errAssistanceFingerprint},
		"mixed algorithms":     {testAssistanceSDP([]string{"sha-256 " + testFingerprint, "sha-512 " + testFingerprint}, relayCandidate), errAssistanceFingerprint},
		"malformed digest":     {testAssistanceSDP([]string{"sha-256 " + strings.ReplaceAll(testFingerprint, ":", "-")}, relayCandidate), errAssistanceFingerprint},
		"no candidates":        {testAssistanceSDP([]string{"sha-256 " + testFingerprint}), errAssistanceNonRelay},
		"host candidate":       {testAssistanceSDP([]string{"sha-256 " + testFingerprint}, relayCandidate, "2 1 udp 2122260223 10.0.0.5 50000 typ host"), errAssistanceNonRelay},
		"srflx candidate":      {testAssistanceSDP([]string{"sha-256 " + testFingerprint}, "3 1 udp 1686052607 198.51.100.7 50000 typ srflx raddr 10.0.0.5 rport 50000"), errAssistanceNonRelay},
		"mdns candidate":       {testAssistanceSDP([]string{"sha-256 " + testFingerprint}, "4 1 udp 2122260223 4f1c.local 50000 typ host"), errAssistanceNonRelay},
		"foreign relay":        {testAssistanceSDP([]string{"sha-256 " + testFingerprint}, "5 1 udp 16777215 203.0.113.9 21000 typ relay raddr 0.0.0.0 rport 0"), errAssistanceNonRelay},
		"truncated candidate":  {testAssistanceSDP([]string{"sha-256 " + testFingerprint}, "6 1 udp 16777215 "+testRelayIP+" 21000 typ"), errAssistanceNonRelay},
		"relay word misplaced": {testAssistanceSDP([]string{"sha-256 " + testFingerprint}, "7 1 udp 16777215 "+testRelayIP+" 21000 relay typ"), errAssistanceNonRelay},
		"other relay address":  {testAssistanceSDP([]string{"sha-256 " + testFingerprint}, "8 1 udp 16777215 ::ffff:192.0.2.11 21000 typ relay"), errAssistanceNonRelay},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := assistanceSDP(test.sdp, relay); !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
}

func TestAssistanceAuditIsCompactAndBounded(t *testing.T) {
	if got := assistanceAudit("cause", "expired", "detail", "", "uid", "1000"); got != "cause=expired uid=1000" {
		t.Fatalf("audit %q", got)
	}
	got := assistanceAudit("reason", strings.Repeat("é", 400))
	if len(got) > assistanceAuditBytes || !utf8.ValidString(got) {
		t.Fatalf("audit length %d valid=%v", len(got), utf8.ValidString(got))
	}
}
