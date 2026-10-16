// SPDX-License-Identifier: Apache-2.0

package feed

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	advisoryv1 "lindm/gen/lindm/advisory/v1"
)

const redHatReplacementLimit = 4

// A permit covers acquisition, verification, ordered normalization and removal,
// not just the HTTP request. All clients and refreshes share this file budget.
var redHatReplacementSlots = make(chan struct{}, redHatReplacementLimit)

type redHatReplacement struct {
	name     string
	modified int64
	config   *advisoryv1.FeedSource
	verified verifiedCSAF
	done     chan error
}

// Load only a bounded lexical batch, releasing the single SQLite connection
// before any document transaction starts. Completed paths leave the partial
// missing-document index only after their exact authenticated digest is stored.
func (p *redHatCheckpoint) replacementBatch(ctx context.Context, stager *redHatStager, batch []redHatReplacement) (count int, err error) {
	rows, err := stager.db.QueryContext(ctx, `SELECT path,modified FROM snapshot_documents WHERE distribution=? AND digest IS NULL ORDER BY path LIMIT ?`, p.distribution, len(batch))
	if err != nil {
		return 0, err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		if err := rows.Scan(&batch[count].name, &batch[count].modified); err != nil {
			return 0, err
		}
		count++
	}
	return count, rows.Err()
}

// One coordinator submits lexically and consumes lexically, but selects between
// the next global permit and the oldest submitted result. It never waits only
// for a permit while holding completed files, so concurrent feeds cannot each
// hold part of the budget and deadlock waiting to fill their batches. Workers
// never touch SQLite. Buffered results let every worker exit during cleanup.
func runRedHatReplacementBatch(ctx context.Context, batch []redHatReplacement, acquire func(context.Context, *advisoryv1.FeedSource, *verifiedCSAF) error, consume func(context.Context, *redHatReplacement) error) (err error) {
	ctx, cancel := context.WithCancelCause(ctx)
	submitted, consumed := 0, 0
	defer func() {
		cancel(err)
		for ; consumed < submitted; consumed++ {
			replacement := &batch[consumed]
			<-replacement.done
			err = errors.Join(err, replacement.verified.close())
			<-redHatReplacementSlots
		}
	}()
	for consumed < len(batch) {
		var permit chan struct{}
		if submitted < len(batch) {
			permit = redHatReplacementSlots
		}
		var ready <-chan error
		if consumed < submitted {
			ready = batch[consumed].done
		}
		select {
		case permit <- struct{}{}:
			if cause := context.Cause(ctx); cause != nil {
				<-redHatReplacementSlots
				return cause
			}
			replacement := &batch[submitted]
			submitted++
			go func() {
				err := acquire(ctx, replacement.config, &replacement.verified)
				if err != nil {
					err = fmt.Errorf("feed: acquire Red Hat replacement %s: %w", replacement.name, err)
					cancel(err)
				}
				replacement.done <- err
			}()
		case acquisitionErr := <-ready:
			replacement := &batch[consumed]
			resultErr := context.Cause(ctx)
			if resultErr == nil {
				resultErr = acquisitionErr
			}
			if resultErr == nil && replacement.verified.signedAt.UnixNano() < replacement.modified {
				resultErr = fmt.Errorf("feed: Red Hat replacement %s predates captured change checkpoint", replacement.name)
			}
			if resultErr == nil {
				resultErr = consume(ctx, replacement)
			}
			// Release only after close/remove has relinquished the owned file.
			resultErr = errors.Join(resultErr, replacement.verified.close())
			<-redHatReplacementSlots
			consumed++
			if resultErr != nil {
				return resultErr
			}
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	}
	return context.Cause(ctx)
}

func (c *Client) fetchRedHatReplacements(ctx context.Context, source *advisoryv1.FeedSource, checkpoint *redHatCheckpoint, stager *redHatStager, doc *advisoryv1.FeedDocument, progress func() error) error {
	var batch [redHatReplacementLimit]redHatReplacement
	for {
		count, err := checkpoint.replacementBatch(ctx, stager, batch[:])
		if err != nil || count == 0 {
			return err
		}
		for i := range count {
			if batch[i].config == nil {
				batch[i].config = proto.CloneOf(source)
				batch[i].config.Format = advisoryv1.FeedFormat_FEED_FORMAT_REDHAT_CSAF
				batch[i].config.ExpectedSha256 = nil
				batch[i].done = make(chan error, 1)
			}
			location := *checkpoint.directory
			location.Path += batch[i].name
			batch[i].config.Url = location.String()
		}
		if err := runRedHatReplacementBatch(ctx, batch[:count], c.acquireSignedCSAF, func(ctx context.Context, replacement *redHatReplacement) error {
			return c.normalizeRedHatReplacement(ctx, source, checkpoint, stager, doc, replacement, progress)
		}); err != nil {
			return err
		}
	}
}

func (c *Client) normalizeRedHatReplacement(ctx context.Context, source *advisoryv1.FeedSource, checkpoint *redHatCheckpoint, stager *redHatStager, doc *advisoryv1.FeedDocument, replacement *redHatReplacement, progress func() error) error {
	err := acceptRedHatDocument(source, c.validator, stager, doc, func() error {
		return parseRedHatFile(ctx, source, replacement.verified.file, c.validator, stager.add)
	})
	if err != nil && !errors.Is(err, errRedHatNotApplicable) {
		return fmt.Errorf("feed: parse verified CSAF: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := checkpoint.recordReplacement(ctx, stager, replacement.name, replacement.verified.artifact.GetSha256(), replacement.modified, replacement.verified.signedAt); err != nil {
		return err
	}
	return markProgress(progress)
}
