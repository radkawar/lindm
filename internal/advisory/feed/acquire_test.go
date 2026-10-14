// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

func TestAcquireMatchesParseStreamInput(t *testing.T) {
	osv := fixture(t, "ubuntu-USN-6859-1.json")
	tracker := fixture(t, "synthetic-debian-tracker-subset.json")
	updateinfo := fixture(t, "synthetic-fedora44-updateinfo.xml")
	updateDigest := sha256.Sum256(updateinfo)
	var corrupt atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body []byte
		switch r.URL.Path {
		case "/osv.json":
			body = osv
		case "/tracker.json":
			body = tracker
		case "/repodata/advisories.xml":
			body = updateinfo
		case "/repodata/repomd.xml":
			checksum := hex.EncodeToString(updateDigest[:])
			if corrupt.Load() {
				checksum = strings.Repeat("0", 64)
			}
			body = fmt.Appendf(nil, `<repomd xmlns="http://linux.duke.edu/metadata/repo"><data type="updateinfo"><checksum type="sha256">%s</checksum><location href="repodata/advisories.xml"/></data></repomd>`, checksum)
		default:
			http.NotFound(w, r)
			return
		}
		if _, err := w.Write(body); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	client, err := New(server.Client())
	if err != nil {
		t.Fatal(err)
	}

	osvSource := source("ubuntu", "24.04", advisoryv1.FeedFormat_FEED_FORMAT_OSV_JSON)
	osvSource.Url = server.URL + "/osv.json"
	trackerSource := debianTrackerSource("12")
	trackerSource.Url = server.URL + "/tracker.json"
	repomdSource := source("fedora", "44", advisoryv1.FeedFormat_FEED_FORMAT_RPM_REPOMD)
	repomdSource.Architecture, repomdSource.Url = "x86_64", server.URL+"/repodata/repomd.xml"

	for _, test := range []struct {
		name      string
		source    *advisoryv1.FeedSource
		want      []byte
		artifacts int
	}{
		{"osv-json", osvSource, osv, 1},
		{"debian-tracker", trackerSource, tracker, 1},
		{"repomd", repomdSource, updateinfo, 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			acquisition, err := client.Acquire(context.Background(), test.source, &output)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(output.Bytes(), test.want) {
				t.Fatal("acquired bytes differ from served bytes")
			}
			digest := sha256.Sum256(test.want)
			if len(acquisition.Artifacts) != test.artifacts || !bytes.Equal(acquisition.Artifacts[0].GetSha256(), digest[:]) {
				t.Fatalf("artifacts %v", acquisition.Artifacts)
			}
			if acquisition.SnapshotAt != nil {
				t.Fatal("unsigned format reported a snapshot time")
			}
			doc, err := ParseStream(context.Background(), test.source, bytes.NewReader(output.Bytes()), func(*advisoryv1.Advisory) error { return nil }, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(doc.GetSourceSha256(), digest[:]) {
				t.Fatal("parsed digest differs from primary artifact")
			}
		})
	}
	if !strings.HasSuffix(mustAcquire(t, client, repomdSource).Artifacts[1].GetUrl(), "/repodata/repomd.xml") {
		t.Fatal("repomd URL not recorded as second artifact")
	}

	corrupt.Store(true)
	var output bytes.Buffer
	if _, err := client.Acquire(context.Background(), repomdSource, &output); err == nil || output.Len() != 0 {
		t.Fatalf("repomd checksum mismatch accepted or wrote output: %v", err)
	}
	pinned := source("ubuntu", "24.04", advisoryv1.FeedFormat_FEED_FORMAT_OSV_JSON)
	pinned.Url, pinned.ExpectedSha256 = server.URL+"/osv.json", make([]byte, sha256.Size)
	if _, err := client.Acquire(context.Background(), pinned, &output); err == nil || output.Len() != 0 {
		t.Fatalf("pinned digest mismatch accepted or wrote output: %v", err)
	}
}

func mustAcquire(t *testing.T, client *Client, config *advisoryv1.FeedSource) *Acquisition {
	t.Helper()
	acquisition, err := client.Acquire(context.Background(), config, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	return acquisition
}

func TestAcquireRejectsRedHat(t *testing.T) {
	client, err := New(http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	archives := redHatSource("9.8", "standard")
	archives.Format, archives.Url = advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF_ARCHIVES, "https://security.access.redhat.com/data/csaf/v2/"
	for _, config := range []*advisoryv1.FeedSource{redHatSource("9.4", "standard"), archives} {
		if err := client.validator.Validate(config); err != nil {
			t.Fatalf("Red Hat source invalid: %v", err)
		}
		var output bytes.Buffer
		if _, err := client.Acquire(context.Background(), config, &output); !errors.Is(err, ErrOfflineUnsupported) || output.Len() != 0 {
			t.Fatalf("Red Hat acquisition: %v", err)
		}
	}
	if _, err := client.Acquire(context.Background(), nil, &bytes.Buffer{}); err == nil {
		t.Fatal("nil source accepted")
	}
}
