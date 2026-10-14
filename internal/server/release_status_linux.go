// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "lindm/gen/lindm/admin/v1"
	"lindm/internal/serverops"
)

// releaseFeedStatus describes only the latest authenticated private import. It
// never infers Internet-wide freshness or server releases from agent TUF state.
func releaseFeedStatus(now time.Time, installed string, read func() (serverops.ReleaseFeedHealth, error)) *adminv1.ServerStatusCheck {
	check := statusCheck("server_release_feed", statusUnknown, "No authenticated offline server release notice is available.", "Import a current signed private server release bundle.", now)
	health, err := read()
	if err != nil || !health.Verified {
		return check
	}
	if !health.ImportedAt.IsZero() {
		check.EvidenceAt = timestamppb.New(health.ImportedAt)
	}
	if !health.ExpiresAt.IsZero() {
		check.ExpiresAt = timestamppb.New(health.ExpiresAt)
	}
	if health.ImportedAt.IsZero() || health.ImportedAt.After(now.Add(time.Minute)) || health.AvailableVersion == "" {
		check.Summary = "The imported server release notice lacks usable freshness evidence."
		check.NextAction = "Check the server clock and import a current signed notice."
		return check
	}
	if health.InstalledVersion != installed || installed == "" {
		check.Summary = "The imported notice has no current installed-release comparison."
		check.NextAction = "Run the offline release check after the server upgrade."
		return check
	}
	check.Detail = fmt.Sprintf("Installed release: %s; imported release: %s; security update: %t; advisories: %s", installed, health.AvailableVersion, health.SecurityUpdate, strings.Join(health.AdvisoryIDs, ", "))
	if !health.ExpiresAt.IsZero() && !now.Before(health.ExpiresAt) {
		check.State = statusAttention
		check.Summary = "The authenticated server release import has expired."
		check.NextAction = "Import a current signed offline release notice."
		return check
	}
	if health.UpdateAvailable {
		check.State = statusAttention
		check.Summary = "An authenticated import offers a newer server release."
		if health.SecurityUpdate {
			check.Summary = "An authenticated import offers a server security update."
		}
		check.NextAction = "Back up the server, review the notice and apply the signed offline bundle."
		if health.ExpiresAt.IsZero() {
			check.Summary = "A signed import offers a newer release; security-notice freshness is unknown."
		}
		return check
	}
	if health.ExpiresAt.IsZero() {
		check.Summary = "The imported bundle has no current server security notice."
		check.NextAction = "Import a current signed server release notice."
		return check
	}
	check.State = statusOK
	check.Summary = "This authenticated import offers no newer release than the installed version."
	check.NextAction = "Import fresh signed notices to check for later releases."
	return check
}
