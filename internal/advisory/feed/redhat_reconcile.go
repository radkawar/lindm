// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"google.golang.org/protobuf/proto"
	_ "modernc.org/sqlite"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

// redHatStager retains source-wide reconciliation on bounded disk instead of a
// map of all claims. It is private to one verified source refresh and never
// publishes directly. A generation sink receives only the final reconciliation.
type redHatStager struct {
	ctx                              context.Context
	db                               *sql.DB
	tx                               *sql.Tx
	insertClaim, findFix, replaceFix *sql.Stmt
	directory                        string
	count, limit                     uint64
	document                         bool
}

func newRedHatStager(ctx context.Context, source *advisoryv1.FeedSource) (stager *redHatStager, err error) {
	directory, err := os.MkdirTemp("", "lindm-redhat-index-*")
	if err != nil {
		return nil, fmt.Errorf("feed: create RHEL reconciliation stage: %w", err)
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, os.RemoveAll(directory))
		}
	}()
	location := url.URL{Scheme: "file", Path: filepath.Join(directory, "claims.sqlite")}
	db, err := sql.Open("sqlite", location.String())
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, db.Close())
		}
	}()
	db.SetMaxOpenConns(1)
	// Two GiB private database, 8 MiB page cache, on-disk temporaries. Document
	// transactions spill to disk; no persistent WAL or feed-sized map is retained.
	for _, statement := range []string{
		"PRAGMA page_size=4096", "PRAGMA max_page_count=524288", "PRAGMA cache_size=-8192", "PRAGMA temp_store=FILE", "PRAGMA journal_mode=DELETE", "PRAGMA synchronous=OFF",
		`CREATE TABLE claims (sequence INTEGER PRIMARY KEY,cve TEXT NOT NULL,name TEXT NOT NULL,module TEXT NOT NULL,stream TEXT NOT NULL,release TEXT NOT NULL,platform TEXT NOT NULL,source INTEGER NOT NULL,architecture TEXT NOT NULL,fixed TEXT NOT NULL,unknown INTEGER NOT NULL,bare INTEGER NOT NULL,not_affected INTEGER NOT NULL,payload BLOB NOT NULL)`,
		`CREATE TABLE fixes (cve TEXT NOT NULL,name TEXT NOT NULL,module TEXT NOT NULL,stream TEXT NOT NULL,release TEXT NOT NULL,platform TEXT NOT NULL,source INTEGER NOT NULL,architecture TEXT NOT NULL,sequence INTEGER NOT NULL,version TEXT NOT NULL,PRIMARY KEY(cve,name,module,stream,release,platform,source,architecture)) WITHOUT ROWID`,
	} {
		if _, err = db.ExecContext(ctx, statement); err != nil {
			return nil, fmt.Errorf("feed: initialize RHEL reconciliation stage: %w", err)
		}
	}
	return &redHatStager{ctx: ctx, db: db, directory: directory, limit: totalClaimsLimit(source)}, nil
}

func (s *redHatStager) add(record *advisoryv1.Advisory) error {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	if s.count >= s.limit {
		return errors.New("feed: total claims limit exceeded")
	}
	if record == nil || (len(record.Cves) != 1 && (!record.SourceRecordRejected || len(record.Cves) != 0)) {
		return errors.New("feed: RHEL reconciliation requires one CVE per claim")
	}
	cve := ""
	if len(record.Cves) == 1 {
		cve = record.Cves[0]
	}
	if proto.Size(record) > 64<<10 {
		return errors.New("feed: RHEL normalized claim byte limit")
	}
	if s.tx == nil {
		tx, err := s.db.BeginTx(s.ctx, nil)
		if err != nil {
			return err
		}
		s.tx = tx
		s.insertClaim, err = tx.PrepareContext(s.ctx, `INSERT INTO claims VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
		if err != nil {
			return err
		}
		s.findFix, err = tx.PrepareContext(s.ctx, `SELECT version FROM fixes WHERE cve=? AND name=? AND module=? AND stream=? AND release=? AND platform=? AND source=? AND architecture=?`)
		if err != nil {
			return err
		}
		s.replaceFix, err = tx.PrepareContext(s.ctx, `INSERT INTO fixes VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(cve,name,module,stream,release,platform,source,architecture) DO UPDATE SET sequence=excluded.sequence,version=excluded.version`)
		if err != nil {
			return err
		}
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(record)
	if err != nil {
		return err
	}
	s.count++
	_, err = s.insertClaim.ExecContext(s.ctx, s.count, cve, record.PackageName, record.ModuleName, record.ModuleStream, record.PlatformRelease, record.PlatformStream, record.SourcePackage, record.Architecture, record.FixedVersion, record.AssessmentUnknown, record.IntroducedVersion == "" && record.LastAffectedVersion == "", record.NotAffected, payload)
	if err != nil {
		return fmt.Errorf("feed: stage RHEL claim: %w", err)
	}
	if record.FixedVersion != "" && !record.AssessmentUnknown {
		var prior string
		err := s.findFix.QueryRowContext(s.ctx, record.Cves[0], record.PackageName, record.ModuleName, record.ModuleStream, record.PlatformRelease, record.PlatformStream, record.SourcePackage, record.Architecture).Scan(&prior)
		replace := errors.Is(err, sql.ErrNoRows)
		if err != nil && !replace {
			return err
		}
		if !replace {
			comparison, compareErr := Compare("rpm", record.FixedVersion, prior)
			// Match established reconciliation: incomparable or equal fixes retain the
			// first observation; parsing independently validates native EVR shapes.
			replace = compareErr == nil && comparison < 0
		}
		if replace {
			_, err = s.replaceFix.ExecContext(s.ctx, record.Cves[0], record.PackageName, record.ModuleName, record.ModuleStream, record.PlatformRelease, record.PlatformStream, record.SourcePackage, record.Architecture, s.count, record.FixedVersion)
			if err != nil {
				return err
			}
		}
	}
	if !s.document && s.count%500 == 0 {
		return s.commit()
	}
	return nil
}

// documentClaims rolls back both claims and winning-fix indexes when any part of
// a vendor document is rejected. SQLite spills bounded-cache pages to disk.
func (s *redHatStager) documentClaims(parse func() error) error {
	if err := s.commit(); err != nil {
		return err
	}
	before := s.count
	s.document = true
	err := parse()
	s.document = false
	if err == nil {
		return s.commit()
	}
	if s.tx != nil {
		rollbackErr := s.tx.Rollback()
		s.tx = nil
		if rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			return fmt.Errorf("feed: roll back rejected RHEL document: %w", rollbackErr)
		}
	}
	s.count = before
	return err
}

func (s *redHatStager) commit() error {
	if s.tx == nil {
		return nil
	}
	tx := s.tx
	s.tx = nil
	return tx.Commit()
}

func (s *redHatStager) emit(ctx context.Context, consumer func(*advisoryv1.Advisory) error) (err error) {
	if consumer == nil {
		return errors.New("feed: RHEL claim consumer required")
	}
	if err := s.commit(); err != nil {
		return err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT c.payload FROM claims c WHERE
 (c.fixed<>'' AND NOT c.unknown AND EXISTS(SELECT 1 FROM fixes f WHERE f.cve=c.cve AND f.name=c.name AND f.module=c.module AND f.stream=c.stream AND f.release=c.release AND f.platform=c.platform AND f.source=c.source AND f.architecture=c.architecture AND f.sequence=c.sequence))
 OR ((c.fixed='' OR c.unknown) AND NOT(c.bare AND NOT c.not_affected AND EXISTS(SELECT 1 FROM fixes f WHERE f.cve=c.cve AND f.name=c.name AND f.module=c.module AND f.stream=c.stream AND f.release=c.release AND f.platform=c.platform AND f.source=c.source AND (c.architecture='' OR f.architecture=c.architecture OR f.architecture='noarch'))))
 ORDER BY c.sequence`)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return err
		}
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return err
		}
		var record advisoryv1.Advisory
		if err := proto.Unmarshal(payload, &record); err != nil {
			return err
		}
		if err := consumer(&record); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (s *redHatStager) close() error {
	var err error
	if s.tx != nil {
		err = s.tx.Rollback()
		s.tx = nil
		if errors.Is(err, sql.ErrTxDone) {
			err = nil
		}
	}
	return errors.Join(err, s.db.Close(), os.RemoveAll(s.directory))
}
