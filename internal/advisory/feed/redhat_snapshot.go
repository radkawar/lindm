// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"strings"
	"time"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
	"lindm/internal/platform"
)

const redHatIndexBytes = 32 << 20

// redHatCheckpoint is a captured publisher inventory, not an assertion that a
// mutable website remained unchanged while a multi-gigabyte snapshot was parsed.
// Every indexed document is represented by the signed archive or a separately
// verified replacement. The archive signing time still bounds freshness.
type redHatCheckpoint struct {
	distribution string
	directory    *url.URL
	index        []byte
	changes      []byte
	oldestChange time.Time
}

func (c *Client) redHatCheckpoint(ctx context.Context, root *url.URL, distribution string) (*redHatCheckpoint, error) {
	directory := *root
	directory.Path = strings.TrimSuffix(directory.Path, "/") + "/" + distribution + "/"
	checkpoint := &redHatCheckpoint{distribution: distribution, directory: &directory}
	for _, target := range []struct {
		name string
		dst  *[]byte
	}{{"index.txt", &checkpoint.index}, {"changes.csv", &checkpoint.changes}} {
		location := directory
		location.Path += target.name
		raw, err := c.get(ctx, location.String(), redHatIndexBytes)
		if err != nil {
			return nil, err
		}
		*target.dst = raw
	}
	// A missing/new document cannot race the index/change capture. Existing
	// documents may advance after this checkpoint; their current signed version
	// is acceptable, but never renews this snapshot's conservative age bound.
	for _, target := range []struct {
		name string
		raw  []byte
	}{{"index.txt", checkpoint.index}, {"changes.csv", checkpoint.changes}} {
		location := directory
		location.Path += target.name
		raw, err := c.get(ctx, location.String(), redHatIndexBytes)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(raw, target.raw) {
			return nil, errors.New("feed: Red Hat index changed during checkpoint capture")
		}
	}
	return checkpoint, nil
}

func redHatDocumentPath(value, distribution string) bool {
	if path.Clean(value) != value || strings.ContainsAny(value, "\\%?#:\t\r\n ") {
		return false
	}
	year, name, ok := strings.Cut(value, "/")
	if !ok || len(year) != 4 || !suseDigits(year) || strings.Contains(name, "/") || !strings.HasSuffix(name, ".json") {
		return false
	}
	// The directory is the publisher's filing year, not necessarily the
	// advisory/CVE identity year. Preserve the indexed path verbatim.
	kind, identity, ok := strings.Cut(strings.TrimSuffix(name, ".json"), "-")
	separator := "_"
	switch distribution {
	case "vex":
		if kind != "cve" {
			return false
		}
		separator = "-"
	case "advisories":
		if kind != "rhsa" && kind != "rhba" && kind != "rhea" {
			return false
		}
	default:
		return false
	}
	identityYear, number, numbered := strings.Cut(identity, separator)
	if !ok || !numbered || len(identityYear) != 4 || !suseDigits(identityYear) || number == "" {
		return false
	}
	for i := range len(number) {
		if number[i] < '0' || number[i] > '9' {
			return false
		}
	}
	return true
}

// The inventory shares the private bounded SQLite stage with normalized claims.
// It never retains a portfolio-sized path/digest map in Go memory.
func (p *redHatCheckpoint) stage(ctx context.Context, stager *redHatStager) (err error) {
	if _, err := stager.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS snapshot_documents (distribution TEXT NOT NULL,path TEXT NOT NULL,modified INTEGER NOT NULL DEFAULT 0,archive_seen INTEGER NOT NULL DEFAULT 0,digest BLOB,PRIMARY KEY(distribution,path)) WITHOUT ROWID`); err != nil {
		return err
	}
	if _, err := stager.db.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS snapshot_documents_missing ON snapshot_documents(distribution,path) WHERE digest IS NULL`); err != nil {
		return err
	}
	tx, err := stager.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, tx.Rollback())
		}
	}()
	insert, err := tx.PrepareContext(ctx, `INSERT INTO snapshot_documents(distribution,path) VALUES(?,?)`)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, insert.Close()) }()
	scanner := bufio.NewScanner(bytes.NewReader(p.index))
	scanner.Buffer(make([]byte, 1024), 4096)
	count := 0
	for scanner.Scan() {
		name := scanner.Text()
		if !redHatDocumentPath(name, p.distribution) || count >= maxEntries {
			return errors.New("feed: invalid or oversized Red Hat document index")
		}
		if _, err := insert.ExecContext(ctx, p.distribution, name); err != nil {
			return fmt.Errorf("feed: duplicate or invalid Red Hat index entry: %w", err)
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if count == 0 {
		return errors.New("feed: empty Red Hat document index")
	}
	update, err := tx.PrepareContext(ctx, `UPDATE snapshot_documents SET modified=max(modified,?) WHERE distribution=? AND path=?`)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, update.Close()) }()
	changes := csv.NewReader(bytes.NewReader(p.changes))
	changes.FieldsPerRecord = 2
	changes.ReuseRecord = true
	for count = 0; ; count++ {
		row, err := changes.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("feed: invalid Red Hat change index: %w", err)
		}
		if count >= maxEntries || !redHatDocumentPath(row[0], p.distribution) {
			return errors.New("feed: invalid or oversized Red Hat change index")
		}
		at, err := time.Parse(time.RFC3339, row[1])
		if err != nil || at.After(time.Now()) {
			return errors.New("feed: invalid Red Hat change timestamp")
		}
		if p.oldestChange.IsZero() || at.Before(p.oldestChange) {
			p.oldestChange = at
		}
		// Removed documents need no resurrection: the captured complete index
		// is the current universe, including the publisher's deletions.
		if _, err := update.ExecContext(ctx, at.UnixNano(), p.distribution, row[0]); err != nil {
			return err
		}
	}
	if p.oldestChange.IsZero() {
		return errors.New("feed: empty Red Hat change index")
	}
	return tx.Commit()
}

func (p *redHatCheckpoint) artifacts() []*advisoryv1.FeedArtifact {
	artifacts := make([]*advisoryv1.FeedArtifact, 0, 2)
	for _, input := range []struct {
		name string
		raw  []byte
	}{{"index.txt", p.index}, {"changes.csv", p.changes}} {
		location := *p.directory
		location.Path += input.name
		digest := sha256.Sum256(input.raw)
		artifacts = append(artifacts, &advisoryv1.FeedArtifact{Url: location.String(), Sha256: digest[:]})
	}
	return artifacts
}

// Archives are assembled before their detached signature is created. Overlay
// every change since the named archive day's start, not merely after signing:
// otherwise a document changed during assembly could retain its older claims.
func redHatArchiveContentFloor(location, distribution string, signedAt time.Time) (time.Time, error) {
	date := strings.TrimSuffix(strings.TrimPrefix(path.Base(location), "csaf_"+distribution+"_"), ".tar.zst")
	floor, err := time.Parse("2006-01-02", date)
	if err != nil || floor.After(signedAt) {
		return time.Time{}, errors.New("feed: invalid Red Hat archive content checkpoint")
	}
	return floor, nil
}

func (p *redHatCheckpoint) archived(ctx context.Context, stager *redHatStager, name string, contentFloor time.Time) (bool, error) {
	if !redHatDocumentPath(name, p.distribution) {
		return false, errors.New("feed: unconfined Red Hat indexed archive document")
	}
	var modified int64
	var seen bool
	err := stager.db.QueryRowContext(ctx, `SELECT modified,archive_seen FROM snapshot_documents WHERE distribution=? AND path=?`, p.distribution, name).Scan(&modified, &seen)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil // Deleted before the captured index checkpoint.
	}
	if err != nil {
		return false, err
	}
	if seen {
		return false, errors.New("feed: duplicate Red Hat archive document")
	}
	if _, err := stager.db.ExecContext(ctx, `UPDATE snapshot_documents SET archive_seen=1 WHERE distribution=? AND path=?`, p.distribution, name); err != nil {
		return false, err
	}
	return modified < contentFloor.UnixNano(), nil
}

func (p *redHatCheckpoint) record(ctx context.Context, stager *redHatStager, name string, digest []byte) error {
	if err := stager.commit(); err != nil {
		return err
	}
	_, err := stager.db.ExecContext(ctx, `UPDATE snapshot_documents SET digest=? WHERE distribution=? AND path=?`, digest, p.distribution, name)
	return err
}

func (p *redHatCheckpoint) recordReplacement(ctx context.Context, stager *redHatStager, name string, digest []byte, modified int64, signedAt time.Time) error {
	if signedAt.UnixNano() < modified {
		return fmt.Errorf("feed: Red Hat replacement %s predates captured change checkpoint", name)
	}
	return p.record(ctx, stager, name, digest)
}

func (p *redHatCheckpoint) summary(ctx context.Context, stager *redHatStager) (_ *advisoryv1.RedHatDistributionSnapshot, err error) {
	rows, err := stager.db.QueryContext(ctx, `SELECT path,digest FROM snapshot_documents WHERE distribution=? ORDER BY path`, p.distribution)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	digest := sha256.New()
	var count uint32
	for rows.Next() {
		var name string
		var sum []byte
		if err := rows.Scan(&name, &sum); err != nil {
			return nil, err
		}
		if len(sum) != sha256.Size {
			return nil, errors.New("feed: incomplete Red Hat indexed document inventory")
		}
		_, _ = io.WriteString(digest, name)
		_, _ = digest.Write([]byte{0})
		_, _ = digest.Write(sum)
		count++
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return &advisoryv1.RedHatDistributionSnapshot{Distribution: p.distribution, DocumentCount: count, DocumentManifestSha256: digest.Sum(nil)}, nil
}

func (c *Client) fetchIndexedRedHatSnapshot(ctx context.Context, source *advisoryv1.FeedSource, stager *redHatStager, doc *advisoryv1.FeedDocument, progress func() error) (time.Time, error) {
	root, err := signedArtifactURL(source.GetUrl())
	if err != nil {
		return time.Time{}, err
	}
	doc.RedhatSnapshot = new(advisoryv1.RedHatSnapshot)
	manifest, oldest, err := c.fetchRedHatArchives(ctx, source, func(input io.Reader, location string, signedAt time.Time) error {
		archive, err := url.Parse(location)
		if err != nil {
			return err
		}
		distribution := path.Base(path.Dir(archive.Path))
		contentFloor, err := redHatArchiveContentFloor(archive.Path, distribution, signedAt)
		if err != nil {
			return err
		}
		checkpoint, err := c.redHatCheckpoint(ctx, root, distribution)
		if err != nil {
			return err
		}
		if err := checkpoint.stage(ctx, stager); err != nil {
			return err
		}
		if checkpoint.oldestChange.After(contentFloor) {
			return errors.New("feed: Red Hat changes do not reach the signed archive checkpoint")
		}
		if err := parseRedHatArchiveNamed(ctx, source, input, func(entry io.Reader, name string) error {
			accept, err := checkpoint.archived(ctx, stager, name, contentFloor)
			if err != nil {
				return err
			}
			if !accept {
				return markProgress(progress)
			}
			digest := sha256.New()
			original := io.TeeReader(entry, digest)
			err = acceptRedHatDocument(source, c.validator, stager, doc, func() error {
				return parseRedHatClaims(ctx, source, original, c.validator, stager.add)
			})
			if err != nil && !errors.Is(err, errRedHatNotApplicable) {
				return err
			}
			if _, err := io.Copy(io.Discard, original); err != nil {
				return err
			}
			if err := checkpoint.record(ctx, stager, name, digest.Sum(nil)); err != nil {
				return err
			}
			return markProgress(progress)
		}); err != nil {
			return err
		}
		doc.Artifacts = append(doc.Artifacts, checkpoint.artifacts()...)
		if err := c.fetchRedHatReplacements(ctx, source, checkpoint, stager, doc, progress); err != nil {
			return err
		}
		summary, err := checkpoint.summary(ctx, stager)
		if err != nil {
			return err
		}
		doc.RedhatSnapshot.Distributions = append(doc.RedhatSnapshot.Distributions, summary)
		return nil
	})
	if err != nil {
		return time.Time{}, err
	}
	if err := bindArtifacts(doc, append(manifest.GetArtifacts(), doc.Artifacts...)); err != nil {
		return time.Time{}, err
	}
	doc.CompleteSnapshot = redHatSnapshotComplete(source, doc.RejectedRecords)
	return oldest, nil
}

func redHatSnapshotComplete(source *advisoryv1.FeedSource, rejected []*advisoryv1.RejectedRecord) bool {
	if !platform.Identify(platform.OSRelease{ID: source.GetDistro(), VersionID: source.GetRelease()}).Advisory.RPMHeaderAuthority {
		return false
	}
	for _, record := range rejected {
		if record.GetUnscoped() || len(record.GetPackageNames()) == 0 {
			return false
		}
	}
	return true
}
