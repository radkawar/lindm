// SPDX-License-Identifier: Apache-2.0
import assert from "node:assert/strict";
import test from "node:test";
import {
  agentUpdateReason,
  agentUpdateState,
  nativeActionReason,
  nativeUpdateStep,
  nativeVerificationEvidence,
} from "../src/features/devices/native-status-copy.ts";

test("device action refusal describes the native prerequisite, not its reason code", () => {
  assert.equal(
    nativeActionReason("no_free_keyslot"),
    "The encrypted volume has no free key slot. Review its keys before retrying.",
  );
  assert.equal(
    nativeActionReason("session_lock_not_qualified"),
    "The device configuration does not allow session locks.",
  );
  assert.equal(
    nativeActionReason("tpm2_resource_manager_unavailable"),
    "The device cannot access its TPM 2.0 resource manager.",
  );
  assert.equal(
    nativeActionReason("local_admin_account_missing"),
    "The selected local account does not exist on the device.",
  );
});

test("agent update results distinguish an interrupted update from no available update", () => {
  assert.equal(agentUpdateState("recovery_required"), "Needs recovery");
  assert.equal(agentUpdateState("no_update"), "No update available");
  assert.equal(agentUpdateState("incomplete"), "Not completed");
  assert.match(agentUpdateReason("native_transaction_incomplete"), /did not finish/);
  assert.match(agentUpdateReason("update_checkpoint_failed"), /could not save its update state/);
  assert.equal(nativeUpdateStep("payload_verify"), "Verify update package");
  assert.equal(nativeUpdateStep("configure"), "Configure installed packages");
});

test("new reason codes never leak into device primary copy or become success", () => {
  const unexpected = "new_native_reason_2099";
  for (const copy of [nativeActionReason(unexpected), agentUpdateReason(unexpected)]) {
    assert.ok(!copy.includes(unexpected));
    assert.match(copy, /Open Details/);
  }
  assert.equal(agentUpdateState(unexpected), "Unknown");
  assert.equal(nativeUpdateStep(unexpected), "Not reported");
  assert.equal(nativeActionReason(""), "The device did not report a cause.");
  assert.equal(agentUpdateReason(""), "No reason reported.");
});

test("native verification keeps safety limits visible and does not claim a power request completed", () => {
  assert.match(
    nativeVerificationEvidence("outcome_unknown_until_contact"),
    /outcome remains unknown/,
  );
  const warning = "Local header destruction only: escrow/header backups are not destroyed.";
  assert.equal(nativeVerificationEvidence(warning), warning);
  assert.match(nativeVerificationEvidence("new_evidence_code"), /Open Details/);
  assert.ok(!nativeVerificationEvidence("new_evidence_code").includes("new_evidence_code"));
});
