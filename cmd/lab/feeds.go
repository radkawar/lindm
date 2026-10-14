// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"lindm/internal/devlab"
)

const feedsUsage = `Usage: lab feeds sources [-families ubuntu,fedora,rhel,debian,suse,arch]
       lab feeds record -repo DIR -lindmd FILE -sources FILE -cache DIR -manifest-out NEW_FILE [-record NEW_FILE]
       lab feeds replay -repo DIR -lindmd FILE -sources FILE -cache DIR -manifest FILE [-record NEW_FILE]

Sources emits strict protobuf JSON AdvisoryConfig. SUSE is one genuine signed
CSAF document, not a full ecosystem export; all other defaults are complete
vendor exports for their configured scope. Custom supported configs are accepted.
Record acquires real vendor HTTPS bytes into the acceptance cache and writes an
immutable URL/SHA-256/size manifest after successful staging and publication.
Replay performs no vendor requests: digest-checked blobs use verified loopback
TLS and the real parser/database stage/reconcile/fenced publication path. Replay
is NOT freshness or vendor TLS evidence. Missing/corrupt blobs fail, never fetch.

Both modes create and remove a disposable authority database through the shared
repo's dev fixture credentials (never DSNs in argv/environment). -lindmd must be
a stamped prebuilt server from the same checkout as this lab executable. Compare
the same source file and immutable manifest with baseline and candidate binaries.
JSON includes per-source publication times/counts, committed publication digests,
refresh wall time, digest overhead, runtime/memory context and failure details.
Use /usr/bin/time -v for process-tree CPU and peak RSS; PostgreSQL is external.
`

func runFeeds(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		_, err := io.WriteString(stdout, feedsUsage)
		return err
	}
	verb := args[0]
	if verb != "sources" && verb != "record" && verb != "replay" {
		return fmt.Errorf("unknown feeds command %q; use lab feeds -h", verb)
	}
	flags := flag.NewFlagSet("feeds "+verb, flag.ContinueOnError)
	flags.SetOutput(stderr)
	if verb == "sources" {
		families := flags.String("families", "ubuntu,fedora,rhel,debian,suse,arch", "comma-separated source families (SUSE: single signed CSAF)")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("feeds sources accepts no positional arguments")
		}
		cfg, err := devlab.FeedBenchmarkSources(strings.Split(*families, ","))
		if err != nil {
			return err
		}
		encoded, err := (protojson.MarshalOptions{Indent: "  "}).Marshal(cfg)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(stdout, string(encoded))
		return err
	}
	repo := flags.String("repo", ".", "shared repository with running dev PostgreSQL and protected fixture credentials")
	binary := flags.String("lindmd", "", "stamped prebuilt lindmd from this lab binary's checkout")
	sources := flags.String("sources", "", "explicit strict protobuf JSON AdvisoryConfig")
	cache := flags.String("cache", "", "explicit persistent acceptance cache directory containing digest-named blobs")
	manifest := flags.String("manifest", "", "replay only: immutable JSON artifact array (URL/SHA-256/bytes)")
	manifestOut := flags.String("manifest-out", "", "record only: new immutable artifact manifest file")
	record := flags.String("record", "", "new private JSON timing/evidence file (also written on refresh failure)")
	byteBudget := flags.Int64("byte-budget", 4<<30, "maximum total acquired/replayed bytes, including companion artifacts")
	timeout := flags.Duration("timeout", 2*time.Hour, "overall deadline, including fixture startup, refresh and digest pass")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || *binary == "" || *sources == "" || *cache == "" || *byteBudget <= 0 || *timeout <= 0 {
		return errors.New("feeds record/replay requires -lindmd, -sources, -cache and positive budgets; no positional arguments")
	}
	if verb == "record" && (*manifest != "" || *manifestOut == "") || verb == "replay" && (*manifest == "" || *manifestOut != "") {
		return errors.New("record requires only -manifest-out; replay requires only -manifest")
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	collector := &feedTimingCollector{}
	previous := slog.Default()
	slog.SetDefault(slog.New(&feedTimingHandler{base: slog.NewJSONHandler(stderr, nil), collector: collector}))
	defer slog.SetDefault(previous)
	started := time.Now()
	result := feedCommandResult{Runtime: feedRuntimeContext(), SourcesPath: *sources, CacheDirectory: *cache, ManifestPath: *manifest}
	timing, err := timeFeedFixture(ctx, *repo, *binary, devlab.FeedTimingOptions{CacheDirectory: *cache, SourcesPath: *sources, ManifestPath: *manifest, ByteBudget: *byteBudget, Timeout: *timeout})
	result.Timing = timing
	result.TotalSeconds = time.Since(started).Seconds()
	result.Sources = collector.results()
	if err == nil && verb == "record" {
		artifacts := result.Timing.Refresh.Artifacts
		slices.SortFunc(artifacts, func(a, b devlab.AcceptanceFeedArtifact) int { return strings.Compare(a.URL, b.URL) })
		err = writeLabEvidence(io.Discard, *manifestOut, artifacts)
	}
	if err != nil {
		result.Error = err.Error()
	}
	return errors.Join(err, writeLabEvidence(stdout, *record, result))
}

func timeFeedFixture(ctx context.Context, repository, binary string, options devlab.FeedTimingOptions) (_ *devlab.FeedTimingResult, resultErr error) {
	fixture, err := devlab.OpenLocalConsoleAuthorityFixture(ctx, repository, binary)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, fixture.Close()) }()
	return fixture.TimeFeedRefresh(ctx, options)
}

type feedCommandResult struct {
	Timing         *devlab.FeedTimingResult `json:"timing,omitempty"`
	Sources        []feedSourceTiming       `json:"sources"`
	Runtime        map[string]any           `json:"runtime"`
	SourcesPath    string                   `json:"sources_path"`
	CacheDirectory string                   `json:"cache_directory"`
	ManifestPath   string                   `json:"manifest_path,omitempty"`
	TotalSeconds   float64                  `json:"total_seconds_including_fixture"`
	Error          string                   `json:"error,omitempty"`
}

func feedRuntimeContext() map[string]any {
	result := map[string]any{"go_version": runtime.Version(), "goos": runtime.GOOS, "goarch": runtime.GOARCH, "logical_cpus": runtime.NumCPU(), "gomaxprocs": runtime.GOMAXPROCS(0), "gogc_env": os.Getenv("GOGC"), "gomemlimit_env": os.Getenv("GOMEMLIMIT"), "database": "disposable database on shared dev PostgreSQL; database CPU/RSS excluded from process metrics"}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" || setting.Key == "vcs.modified" {
				result[setting.Key] = setting.Value
			}
		}
	}
	return result
}

type feedSourceTiming struct {
	FeedID   string  `json:"feed_id"`
	Seconds  float64 `json:"publication_seconds"`
	Emitted  int64   `json:"emitted_records"`
	Unique   int64   `json:"unique_records"`
	Rejected int64   `json:"rejected_records"`
}

type feedTimingCollector struct {
	mu      sync.Mutex
	sources []feedSourceTiming
}

func (c *feedTimingCollector) results() []feedSourceTiming {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := slices.Clone(c.sources)
	slices.SortFunc(result, func(a, b feedSourceTiming) int { return strings.Compare(a.FeedID, b.FeedID) })
	return result
}

type feedTimingHandler struct {
	base      slog.Handler
	collector *feedTimingCollector
}

func (h *feedTimingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.base.Enabled(ctx, level)
}
func (h *feedTimingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &feedTimingHandler{base: h.base.WithAttrs(attrs), collector: h.collector}
}
func (h *feedTimingHandler) WithGroup(name string) slog.Handler {
	return &feedTimingHandler{base: h.base.WithGroup(name), collector: h.collector}
}
func (h *feedTimingHandler) Handle(ctx context.Context, record slog.Record) error {
	if record.Message == "advisory feed published" {
		var result feedSourceTiming
		record.Attrs(func(attr slog.Attr) bool {
			switch attr.Key {
			case "feed_id":
				result.FeedID = attr.Value.String()
			case "elapsed":
				result.Seconds = attr.Value.Duration().Seconds()
			case "emitted_count":
				result.Emitted = feedTimingCount(attr.Value)
			case "unique_count":
				result.Unique = feedTimingCount(attr.Value)
			case "rejected_count":
				result.Rejected = feedTimingCount(attr.Value)
			}
			return true
		})
		h.collector.mu.Lock()
		h.collector.sources = append(h.collector.sources, result)
		h.collector.mu.Unlock()
	}
	return h.base.Handle(ctx, record)
}

func feedTimingCount(value slog.Value) int64 {
	if value.Kind() == slog.KindUint64 {
		// Publication counters are bounded by the source total-claims limit.
		return int64(value.Uint64())
	}
	return value.Int64()
}
