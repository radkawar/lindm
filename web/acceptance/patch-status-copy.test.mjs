// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";
import {
  patchRunRebootReason,
  patchStatusUnavailableReason,
} from "../src/features/devices/patch-status-copy.ts";

for (const [reason, explanation] of [
  ["patch_status_not_computed", "has not reported update status yet"],
  ["patch_status_invalid", "update status report is invalid"],
  ["patch_status_boot_id_unavailable", "cannot identify its current startup"],
  ["patch_status_previous_boot", "from an earlier startup"],
]) {
  test(`unavailable patch status explains ${reason} without claiming an update result`, () => {
    const text = patchStatusUnavailableReason(reason);
    assert.ok(text.includes(explanation));
    assert.match(text, /[Rr]equest fresh inventory/);
    assert.ok(!text.includes(reason));
    assert.doesNotMatch(text, /up to date|succeeded|installed/i);
  });
}

for (const reason of ["future_native_reason", "", "constructor", "__proto__"]) {
  test(`unknown patch reason ${JSON.stringify(reason)} retains an unavailable result`, () => {
    assert.equal(
      patchStatusUnavailableReason(reason),
      "The device cannot report update status. Check Details and request fresh inventory.",
    );
  });
}

for (const [reason, explanation] of [
  ["policy_never", "The update policy does not schedule a reboot."],
  ["native_power_already_pending", "Another power action is pending on this device."],
  ["native_power_inhibited", "A device power inhibitor blocked the reboot."],
  ["reboot_deadline_elapsed", "The deadline for the reboot has passed."],
  ["no_window_before_deadline", "No reboot window was available before the deadline."],
]) {
  test(`patch run explains reboot reason ${reason}`, () => {
    assert.equal(patchRunRebootReason(reason), explanation);
    assert.ok(!explanation.includes(reason));
  });
}

test("an unknown reboot reason remains diagnostic evidence, not a scheduled reboot", () => {
  assert.equal(
    patchRunRebootReason("future_reboot_reason"),
    "The device reported a reboot reason. Check Details.",
  );
  assert.equal(
    patchRunRebootReason("__proto__"),
    "The device reported a reboot reason. Check Details.",
  );
});
