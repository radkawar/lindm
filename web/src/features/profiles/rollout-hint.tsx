// SPDX-License-Identifier: Apache-2.0

import { Link } from "@tanstack/react-router";
import { usePrincipal } from "@/hooks/use-permissions";
import { canPermission } from "@/lib/permissions";

// The one statement of what publishing does, shown once per screen beside the
// action it qualifies: a published version reaches devices only by a rollout.
export function RolloutHint() {
  const principal = usePrincipal();
  return (
    <p data-profile-rollout-hint className="text-sm text-muted-foreground">
      Publishing does not change devices.{" "}
      {canPermission(principal, "resources.assign", true) ? (
        <>
          Roll a profile out from{" "}
          <Link to="/rollouts" className="underline underline-offset-4">
            Rollouts
          </Link>
          .
        </>
      ) : (
        "Ask an administrator with full rollout access to roll out the profile."
      )}
    </p>
  );
}
