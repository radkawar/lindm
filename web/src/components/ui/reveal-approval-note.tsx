// SPDX-License-Identifier: Apache-2.0
// Project additions: Apache-2.0; shadcn-derived portions: MIT.
// Copyright (c) 2023 shadcn; see web/LICENSE.shadcn for the retained MIT notice.

import { RevealApprovalRule, type RevealApproval } from "../../../gen/lindm/admin/v1/secrets_pb";

// The server decides on every reveal whether a second admin must approve it;
// this sentence only explains that decision next to Reveal.
const sentences: Partial<Record<RevealApprovalRule, string>> = {
  [RevealApprovalRule.ANOTHER_APPROVER]: "Needs approval: another admin can approve.",
  [RevealApprovalRule.ONLY_APPROVER]:
    "Only you can reveal this secret. This rule does not require approval.",
  [RevealApprovalRule.SERVER_SETTING]:
    "Needs approval: this server requires a second admin to approve every reveal.",
  [RevealApprovalRule.AUTHORIZATION_POLICY]:
    "Needs approval: your role requires a second admin to approve reveals.",
};

// Unknown when the decision was not loaded or names a rule this console
// doesn't know: callers then offer both Reveal and Request approval.
export function revealApprovalRequired(approval: RevealApproval | undefined): boolean | null {
  if (!approval || sentences[approval.rule] === undefined) return null;
  return approval.required;
}

export function RevealApprovalNote({ approval }: { approval: RevealApproval | undefined }) {
  const sentence = approval ? sentences[approval.rule] : undefined;
  if (!sentence) return null;
  return (
    <p data-slot="reveal-approval" className="text-sm">
      {sentence}
    </p>
  );
}
