package targeting

import (
	"bytes"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	policyv1 "lindm/gen/lindm/policy/v1"
	"lindm/internal/targeting/targetingdb"
)

func previewDigestFixture() *evaluation {
	id := uuid.MustParse("00000000-0000-4000-8000-000000000001")
	generation := uuid.MustParse("00000000-0000-4000-8000-000000000002")
	stamp := pgtype.Timestamptz{Time: time.Unix(1000, 0).UTC(), Valid: true}
	return &evaluation{input: inputs{
		Device: targetingdb.TargetingDeviceRow{
			ID: id, CurrentGenerationID: &generation, State: "active",
			Hostname: "canary", OsID: "debian", OsVersion: "13", Architecture: "amd64",
			HostnameStatus: 1, OsIDStatus: 1, OsVersionStatus: 1,
			HostSequence: 1, HostDigest: []byte("host"), HostReceivedAt: stamp, LastSeenAt: stamp,
			Metadata: []byte(`{"attributes":{"rack":{"intValue":"0"}}}`),
			Labels:   []string{"canary"}, Groups: []string{id.String()},
			PreviousPreviewID: "previous", ResourceAssignmentID: "execution",
		},
		Assignments:   []*policyv1.TargetCandidate{{Revision: 1, Match: included}},
		Groups:        map[string]groupInput{"group": {ID: id, Kind: 2, Revision: 1, Definition: []byte("definition"), AttributeDefinitions: map[string][]byte{"rack": []byte("int")}, Match: included}},
		Rollouts:      map[string]*rolloutInput{"rollout": {Revision: 1}},
		CatalogDigest: []byte("catalog"),
	}}
}

func mustPreviewInputDigest(t *testing.T, e *evaluation) []byte {
	t.Helper()
	got, err := inputDigest(e)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestPreviewInputDigestHeartbeatDependency(t *testing.T) {
	for _, relevant := range []bool{false, true} {
		t.Run(map[bool]string{false: "unrelated heartbeat", true: "last-seen predicate"}[relevant], func(t *testing.T) {
			e := previewDigestFixture()
			group := e.input.Groups["group"]
			group.UsesLastSeen = relevant
			e.input.Groups["group"] = group
			before := mustPreviewInputDigest(t, e)
			if !bytes.Equal(before, mustPreviewInputDigest(t, e)) {
				t.Fatal("unchanged input digest is not deterministic")
			}
			e.input.Device.LastSeenAt.Time = e.input.Device.LastSeenAt.Time.Add(time.Second)
			if equal := bytes.Equal(before, mustPreviewInputDigest(t, e)); equal == relevant {
				t.Fatalf("heartbeat digest equality = %v, relevant predicate = %v", equal, relevant)
			}
			if !e.input.Device.LastSeenAt.Valid || e.input.Device.LastSeenAt.Time.Unix() != 1001 {
				t.Fatal("digest computation mutated the device row")
			}
			e.input.Device.LastSeenAt = pgtype.Timestamptz{}
			if equal := bytes.Equal(before, mustPreviewInputDigest(t, e)); equal == relevant {
				t.Fatalf("missing last-seen digest equality = %v, relevant predicate = %v", equal, relevant)
			}
		})
	}
}

func TestPreviewInputDigestRetainsMembershipFences(t *testing.T) {
	changes := map[string]func(*inputs){
		"device":                func(in *inputs) { in.Device.ID = uuid.Nil },
		"generation":            func(in *inputs) { in.Device.CurrentGenerationID = nil },
		"state":                 func(in *inputs) { in.Device.State = "retired" },
		"hostname":              func(in *inputs) { in.Device.Hostname = "other" },
		"os ID":                 func(in *inputs) { in.Device.OsID = "fedora" },
		"os version":            func(in *inputs) { in.Device.OsVersion = "14" },
		"hostname status":       func(in *inputs) { in.Device.HostnameStatus = 2 },
		"os ID status":          func(in *inputs) { in.Device.OsIDStatus = 2 },
		"os version status":     func(in *inputs) { in.Device.OsVersionStatus = 2 },
		"host sequence":         func(in *inputs) { in.Device.HostSequence++ },
		"host digest":           func(in *inputs) { in.Device.HostDigest = []byte("new observation") },
		"host freshness":        func(in *inputs) { in.Device.HostReceivedAt.Time = in.Device.HostReceivedAt.Time.Add(time.Second) },
		"architecture":          func(in *inputs) { in.Device.Architecture = "arm64" },
		"attributes":            func(in *inputs) { in.Device.Metadata = []byte(`{}`) },
		"labels":                func(in *inputs) { in.Device.Labels = nil },
		"static membership":     func(in *inputs) { in.Device.Groups = nil },
		"previous preview":      func(in *inputs) { in.Device.PreviousPreviewID = "superseding" },
		"execution head":        func(in *inputs) { in.Device.ResourceAssignmentID = "superseding" },
		"assignment revision":   func(in *inputs) { in.Assignments[0].Revision++ },
		"assignment membership": func(in *inputs) { in.Assignments[0].Match = excluded },
		"catalog":               func(in *inputs) { in.CatalogDigest = []byte("new excluded assignment") },
		"group revision":        func(in *inputs) { g := in.Groups["group"]; g.Revision++; in.Groups["group"] = g },
		"group definition":      func(in *inputs) { g := in.Groups["group"]; g.Definition = []byte("changed"); in.Groups["group"] = g },
		"group membership":      func(in *inputs) { g := in.Groups["group"]; g.Match = excluded; in.Groups["group"] = g },
		"attribute definition":  func(in *inputs) { in.Groups["group"].AttributeDefinitions["rack"] = []byte("bool") },
		"rollout revision":      func(in *inputs) { in.Rollouts["rollout"].Revision++ },
		"rollout pause":         func(in *inputs) { in.Rollouts["rollout"].Paused = true },
		"rollout ring":          func(in *inputs) { in.Rollouts["rollout"].RingIndex++ },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			e := previewDigestFixture()
			before := mustPreviewInputDigest(t, e)
			change(&e.input)
			if bytes.Equal(before, mustPreviewInputDigest(t, e)) {
				t.Fatal("changed membership fence retained the preview digest")
			}
		})
	}
}
