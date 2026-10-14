// SPDX-License-Identifier: Apache-2.0

import { Link } from "@tanstack/react-router";

// The one statement of what publishing does, shown once per screen beside the
// action it qualifies: a published version reaches devices only by a rollout.
export function RolloutHint() {
  return (
    <p data-profile-rollout-hint className="text-sm text-muted-foreground">
      Publishing doesn't change devices. Roll a profile out from{" "}
      <Link to="/rollouts" className="underline underline-offset-4">
        Rollouts
      </Link>
      .
    </p>
  );
}
