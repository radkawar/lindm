// SPDX-License-Identifier: Apache-2.0

//go:build integration

package assistance

import (
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"

	adminv1 "lindm/gen/lindm/admin/v1"
	agentv1 "lindm/gen/lindm/agent/v1"
	"lindm/internal/device/devicedb"
	"lindm/internal/identity"
)

func assistanceAuthoritySession(t *testing.T, f *assistanceFixture, id uuid.UUID) devicedb.AssistanceSession {
	t.Helper()
	row, err := devicedb.New(f.svc.Pool).GetAssistanceSession(f.ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	return row
}

func assistanceAuthoritySyncDirective(t *testing.T, f *assistanceFixture, id uuid.UUID) *agentv1.AssistanceDirective {
	t.Helper()
	for _, directive := range f.sync(t) {
		if directive.GetInvitation().GetSessionId() == id.String() {
			return directive
		}
	}
	t.Fatalf("sync omitted assistance session %s", id)
	return nil
}

func TestAssistanceAuthorityStaleObservationPreservesReplacement(t *testing.T) {
	for _, observation := range []struct {
		name          string
		hasSession    bool
		lostAuthority bool
		otherOperator bool
	}{
		{name: "observe_none_then_create"},
		{name: "observe_A_then_stop_create_B_same_operator", hasSession: true},
		{name: "observe_A_then_stop_create_B_other_operator", hasSession: true, otherOperator: true},
		{name: "observe_A_without_authority_then_stop_create_B", hasSession: true, lostAuthority: true, otherOperator: true},
	} {
		t.Run(observation.name, func(t *testing.T) {
			for _, boundary := range []struct {
				name    string
				expired bool
			}{
				{name: "live_create_lease"},
				{name: "at_create_lease_expiry", expired: true},
			} {
				t.Run(boundary.name, func(t *testing.T) {
					f := newAssistanceFixture(t, 0)
					var original *adminv1.AssistanceSession
					if observation.hasSession {
						original = f.create(t, agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, 0, "")
					}
					if observation.lostAuthority {
						if _, err := f.conn.Exec(f.ctx, "UPDATE local_accounts SET enabled=false WHERE id=$1", f.creator.ID); err != nil {
							t.Fatal(err)
						}
					}

					// Split the existing observe/locked-refresh phases. Stop and Create
					// commit in between, deterministically winning the SQL locks without
					// sleeps, scheduler-dependent goroutines or a production test hook.
					observedID, authorization, err := f.svc.observeAssistanceAuthority(f.ctx, f.principal.DeviceID)
					if err != nil {
						t.Fatal(err)
					}
					wantObserved := uuid.Nil
					if original != nil {
						wantObserved = uuid.MustParse(original.GetId())
					}
					if observedID != wantObserved || (authorization != nil) != (observation.hasSession && !observation.lostAuthority) {
						t.Fatalf("unexpected pre-lock observation: session=%s authorization=%t", observedID, authorization != nil)
					}
					if original != nil {
						stopped, err := f.svc.StopAssistanceSession(f.otherCtx, connect.NewRequest(&adminv1.StopAssistanceSessionRequest{SessionId: original.GetId()}))
						if err != nil {
							t.Fatal(err)
						}
						if stopped.Msg.GetSession().GetState() != adminv1.AssistanceState_ASSISTANCE_STATE_ENDED {
							t.Fatal("original invitation did not stop before replacement")
						}
					}
					creatorCtx := f.creatorCtx
					if observation.otherOperator {
						creatorCtx = f.otherCtx
					}
					created, err := f.svc.CreateAssistanceSession(creatorCtx, connect.NewRequest(f.createRequest(agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, 0, "")))
					if err != nil {
						t.Fatal(err)
					}
					id := uuid.MustParse(created.Msg.GetSession().GetId())
					before := assistanceAuthoritySession(t, f, id)
					if id == observedID || before.State != assistanceRequested || !before.AuthorizedUntil.Valid || !f.now.Before(before.AuthorizedUntil.Time) {
						t.Fatal("replacement did not establish its own live Create-time lease")
					}
					if boundary.expired {
						f.now = before.AuthorizedUntil.Time
					}

					for range 2 {
						if !boundary.expired {
							f.advance(time.Second)
						}
						// Keep Sync's identity -> device -> session lock order and its
						// deadline check before applying the stale observation.
						err := f.svc.assistanceTx(f.ctx, authorization, identity.PermissionViewRemoteAssistance, func(q *devicedb.Queries, revoked *assistanceRevocations) error {
							device, err := f.svc.LockAuthority(f.ctx, q, f.principal)
							if err != nil {
								return err
							}
							if err := enforceOpenAssistance(f.ctx, q, f.principal.DeviceID, device.Now, revoked); err != nil {
								return err
							}
							return f.svc.refreshAssistanceAuthority(f.ctx, q, f.principal.DeviceID, observedID, authorization, device.Now, revoked)
						})
						if err != nil {
							t.Fatal(err)
						}
						after := assistanceAuthoritySession(t, f, id)
						if !after.AuthorizedUntil.Time.Equal(before.AuthorizedUntil.Time) {
							t.Fatalf("stale observation changed replacement lease: got %v, want %v", after.AuthorizedUntil.Time, before.AuthorizedUntil.Time)
						}
						if boundary.expired {
							if after.State != assistanceEnded || after.EndCause != int16(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST) || after.EndDetail != "operator_authorization_expired" {
								t.Fatalf("stale observation bypassed replacement expiry: state=%d detail=%q", after.State, after.EndDetail)
							}
						} else if after.State != assistanceRequested || after.EndedAt.Valid {
							t.Fatalf("stale observation terminated replacement: state=%d detail=%q", after.State, after.EndDetail)
						}
						if f.relay.Ended(id) != boundary.expired {
							t.Fatalf("replacement relay revocation=%t, want %t", f.relay.Ended(id), boundary.expired)
						}
					}
					var endAudits int
					if err := f.conn.QueryRow(f.ctx, "SELECT count(*) FROM audit_events WHERE resource_id=$1 AND action='assistance.end'", id).Scan(&endAudits); err != nil {
						t.Fatal(err)
					}
					wantAudits := 0
					if boundary.expired {
						wantAudits = 1
					}
					if endAudits != wantAudits {
						t.Fatalf("replacement end audits=%d, want %d", endAudits, wantAudits)
					}

					// The stale sync must deliver exactly the independently established
					// lease, not a new window measured from this poll.
					directive, err := f.svc.assistanceDirective(assistanceAuthoritySession(t, f, id))
					if err != nil {
						t.Fatal(err)
					}
					if directive.GetTerminate() != boundary.expired || !directive.GetAuthorizedUntil().AsTime().Equal(before.AuthorizedUntil.Time) {
						t.Fatal("stale sync directive changed replacement authority")
					}
					if next := assistanceAuthoritySyncDirective(t, f, id); next.GetTerminate() != boundary.expired {
						t.Fatal("next full sync changed the replacement's lifetime outcome")
					}
					if !boundary.expired {
						// A subsequent full Sync must observe B's creator afresh, not keep
						// A's authority or treat a previous mismatch as continuing consent.
						if _, err := f.conn.Exec(f.ctx, "UPDATE local_accounts SET enabled=false WHERE id=$1", before.OperatorID); err != nil {
							t.Fatal(err)
						}
						if next := assistanceAuthoritySyncDirective(t, f, id); !next.GetTerminate() || next.GetTerminateCause() != agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST {
							t.Fatal("next sync failed to observe replacement creator authority loss")
						}
						if row := assistanceAuthoritySession(t, f, id); row.EndDetail != "operator_authorization_lost" {
							t.Fatalf("replacement ended for %q instead of fresh authority loss", row.EndDetail)
						}
					}
				})
			}
		})
	}
}

func TestAssistanceAuthorityLossEndsSameObservedSession(t *testing.T) {
	for _, loss := range []string{"missing", "expired_observation", "mismatched_actor", "expired_session_lease"} {
		t.Run(loss, func(t *testing.T) {
			f := newAssistanceFixture(t, 0)
			session := f.create(t, agentv1.AssistanceMode_ASSISTANCE_MODE_VIEW, 0, "")
			id := uuid.MustParse(session.GetId())
			if loss == "missing" {
				if _, err := f.conn.Exec(f.ctx, "UPDATE local_accounts SET enabled=false WHERE id=$1", f.creator.ID); err != nil {
					t.Fatal(err)
				}
			}
			observedID, authorization, err := f.svc.observeAssistanceAuthority(f.ctx, f.principal.DeviceID)
			if err != nil {
				t.Fatal(err)
			}
			if observedID != id || (authorization == nil) != (loss == "missing") {
				t.Fatal("did not observe the original session's authority")
			}
			wantDetail := "operator_authorization_lost"
			switch loss {
			case "expired_observation":
				// Advance only the device clock so the real approval is expired at
				// consumption, without waiting for the identity service's wall clock.
				f.now = authorization.ExpiresAt().Add(time.Second)
			case "mismatched_actor":
				other, ok := identity.PrincipalFromContext(f.otherCtx)
				if !ok {
					t.Fatal("missing other operator")
				}
				authorization, err = f.svc.Identity.AuthorizeFresh(f.ctx, other.ID, identity.PermissionViewRemoteAssistance)
				if err != nil {
					t.Fatal(err)
				}
			case "expired_session_lease":
				// Fresh authority cannot resurrect a session whose existing lease
				// has already elapsed, even when the operator still has permission.
				if _, err := f.conn.Exec(f.ctx, "UPDATE assistance_sessions SET authorized_until=$2 WHERE id=$1", id, f.now); err != nil {
					t.Fatal(err)
				}
				wantDetail = "operator_authorization_expired"
			}
			before := assistanceAuthoritySession(t, f, id)
			err = f.svc.assistanceTx(f.ctx, authorization, identity.PermissionViewRemoteAssistance, func(q *devicedb.Queries, revoked *assistanceRevocations) error {
				device, err := f.svc.LockAuthority(f.ctx, q, f.principal)
				if err != nil {
					return err
				}
				// Exercise refresh's own same-session fail-closed checks directly;
				// the race test above separately covers Sync's prior deadline check.
				return f.svc.refreshAssistanceAuthority(f.ctx, q, f.principal.DeviceID, observedID, authorization, device.Now, revoked)
			})
			if err != nil {
				t.Fatal(err)
			}
			after := assistanceAuthoritySession(t, f, id)
			if after.State != assistanceEnded || after.EndCause != int16(agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST) || after.EndDetail != wantDetail {
				t.Fatalf("same-session authority loss retained support: state=%d detail=%q, want %q", after.State, after.EndDetail, wantDetail)
			}
			if !after.AuthorizedUntil.Time.Equal(before.AuthorizedUntil.Time) {
				t.Fatal("authority loss extended the observed session's lease")
			}
			if !f.relay.Ended(id) {
				t.Fatal("authority loss did not revoke relay credentials")
			}
			if directive := assistanceAuthoritySyncDirective(t, f, id); !directive.GetTerminate() || directive.GetTerminateCause() != agentv1.AssistanceEndCause_ASSISTANCE_END_CAUSE_AUTHORIZATION_LOST {
				t.Fatal("full sync resurrected the ended observed session")
			}
		})
	}
}
