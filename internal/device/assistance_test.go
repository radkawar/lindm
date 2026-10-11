package device

import (
	"errors"
	"maps"
	"net/netip"
	"strings"
	"testing"

	"lindm/internal/device/assistance"

	"lindm/internal/device/core"
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
	got, err := assistance.AssistanceSDP(testAssistanceSDP([]string{"sha-256 " + strings.ToLower(testFingerprint), "SHA-256 " + testFingerprint}, relayCandidate), relay)
	if err != nil || got != "sha-256 "+testFingerprint {
		t.Fatalf("valid relay-only offer: %q %v", got, err)
	}
	other := strings.Replace(testFingerprint, "AB", "00", 1)
	for name, test := range map[string]struct {
		sdp  string
		want error
	}{
		"no fingerprint":       {testAssistanceSDP(nil, relayCandidate), assistance.ErrAssistanceFingerprint},
		"two fingerprints":     {testAssistanceSDP([]string{"sha-256 " + testFingerprint, "sha-256 " + other}, relayCandidate), assistance.ErrAssistanceFingerprint},
		"sha-1":                {testAssistanceSDP([]string{"sha-1 " + testFingerprint[:59]}, relayCandidate), assistance.ErrAssistanceFingerprint},
		"mixed algorithms":     {testAssistanceSDP([]string{"sha-256 " + testFingerprint, "sha-512 " + testFingerprint}, relayCandidate), assistance.ErrAssistanceFingerprint},
		"malformed digest":     {testAssistanceSDP([]string{"sha-256 " + strings.ReplaceAll(testFingerprint, ":", "-")}, relayCandidate), assistance.ErrAssistanceFingerprint},
		"no candidates":        {testAssistanceSDP([]string{"sha-256 " + testFingerprint}), assistance.ErrAssistanceNonRelay},
		"host candidate":       {testAssistanceSDP([]string{"sha-256 " + testFingerprint}, relayCandidate, "2 1 udp 2122260223 10.0.0.5 50000 typ host"), assistance.ErrAssistanceNonRelay},
		"srflx candidate":      {testAssistanceSDP([]string{"sha-256 " + testFingerprint}, "3 1 udp 1686052607 198.51.100.7 50000 typ srflx raddr 10.0.0.5 rport 50000"), assistance.ErrAssistanceNonRelay},
		"mdns candidate":       {testAssistanceSDP([]string{"sha-256 " + testFingerprint}, "4 1 udp 2122260223 4f1c.local 50000 typ host"), assistance.ErrAssistanceNonRelay},
		"foreign relay":        {testAssistanceSDP([]string{"sha-256 " + testFingerprint}, "5 1 udp 16777215 203.0.113.9 21000 typ relay raddr 0.0.0.0 rport 0"), assistance.ErrAssistanceNonRelay},
		"truncated candidate":  {testAssistanceSDP([]string{"sha-256 " + testFingerprint}, "6 1 udp 16777215 "+testRelayIP+" 21000 typ"), assistance.ErrAssistanceNonRelay},
		"relay word misplaced": {testAssistanceSDP([]string{"sha-256 " + testFingerprint}, "7 1 udp 16777215 "+testRelayIP+" 21000 relay typ"), assistance.ErrAssistanceNonRelay},
		"other relay address":  {testAssistanceSDP([]string{"sha-256 " + testFingerprint}, "8 1 udp 16777215 ::ffff:192.0.2.11 21000 typ relay"), assistance.ErrAssistanceNonRelay},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := assistance.AssistanceSDP(test.sdp, relay); !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
}

func TestAuditDetailsPreservesValues(t *testing.T) {
	value := strings.Repeat("é", 400) + " user=not-a-field"
	got := core.AuditDetails("cause", "expired", "detail", value, "empty", "")
	want := map[string]string{"cause": "expired", "detail": value}
	if !maps.Equal(got, want) {
		t.Fatalf("audit details %v, want %v", got, want)
	}
}
