import { randomUUID } from "node:crypto";

// Real administrator UI only. Names carry context; identity is never typed or
// extracted from diagnostic panels. Never read a revealed secret.
const timeout = 30_000;
const groupRemedy =
  "Choose member devices by hostname, OS and last contact; show the resulting named membership before saving.";
const rolloutRemedy =
  "Choose the Finance group and profile version by name, preview all affected devices and conflicts before saving, then review stages and activation separately.";

async function visible(locator) {
  await locator.waitFor({ state: "visible", timeout });
}

function formWithHeading(page, name) {
  return page.locator("form").filter({ has: page.getByRole("heading", { name, exact: true }) });
}

async function shot(ctx, name, screen, taskShaped, generic, remedy, outcome) {
  // The account screen predates data-sensitive. Mark only its secret node for
  // the existing screenshot masker; never extract, replace or log its contents.
  await ctx.page
    .locator('section[aria-label="One-time enrollment secret"] code')
    .evaluateAll((nodes) => nodes.forEach((node) => node.setAttribute("data-sensitive", "true")));
  await ctx.capture(name, { screen, taskShaped, generic, remedy, outcome });
}

async function navigate(ctx, label, heading) {
  const { page } = ctx;
  const nav = page.getByRole("navigation", { name: "Main navigation" });
  if (!(await nav.isVisible())) {
    await page.getByRole("button", { name: "Toggle navigation", exact: true }).click();
    await shot(
      ctx,
      `navigation-${label.toLowerCase()}`,
      "Main navigation",
      "partly",
      "The mobile drawer exposes domain destinations rather than the current job's next step.",
      "Keep the current task and selected group/device context visible across destinations.",
      `The administrator opens navigation to ${label}.`,
    );
  }
  await nav.getByRole("link", { name: label, exact: true }).click();
  // Close the mobile navigation drawer so subsequent captures show the task.
  const drawer = page.getByRole("dialog").filter({ has: nav });
  if (await drawer.isVisible()) await page.keyboard.press("Escape");
  await visible(page.getByRole("heading", { name: heading, exact: true }));
}

function representative(config, department) {
  const devices = config.demo?.Devices ?? [];
  const usable = devices.filter((device) => device.State === "enrolled");
  const device =
    usable.find((entry) => entry.Hostname.toLowerCase().includes(department.toLowerCase())) ??
    usable.find((entry) => /laptop|thinkpad|latitude|workstation/i.test(entry.Hostname)) ??
    usable[0];
  if (!device?.ID || !device.Hostname) throw new Error("representative_device_missing");
  return device;
}

async function start(ctx, id, job) {
  await ctx.visit("/dashboard");
  await shot(
    ctx,
    `${id}-start`,
    "Dashboard / main navigation",
    "partly",
    "The job starts by choosing separate domain destinations rather than a connected task.",
    `Offer a contextual start for ${job} and preserve its selected person, group and device across screens.`,
    "Authenticated administrator starts the job; no changes have been made.",
  );
}

async function chooseNamed(ctx, container, label, name, prefix) {
  const trigger = container.getByRole("button", { name: new RegExp(`^${label} `) });
  await trigger.click();
  // The picker's choices float in a popover outside the container.
  await ctx.page
    .getByRole("combobox", { name: `Search ${label.toLowerCase()}`, exact: true })
    .fill(name);
  const option = ctx.page.getByRole("option").filter({
    has: ctx.page.getByText(name, { exact: true }),
  });
  try {
    await visible(option);
  } catch {
    throw new Error("named_picker_matching_option_not_visible");
  }
  await shot(
    ctx,
    `${prefix}-choices`,
    "Named selection / matching context",
    "yes",
    "The console carries identity internally; the operator reads a name and context.",
    "Keep names and distinguishing context visible, including unavailable saved selections.",
    `The actual picker offers ${name}; no identity was typed or extracted from Details.`,
  );
  await option.click();
}

async function createGroup(ctx, id, department, device) {
  const { page } = ctx;
  await navigate(ctx, "Devices", "Devices");
  await visible(page.getByRole("link", { name: device.Hostname, exact: true }));
  await shot(
    ctx,
    `${id}-representative-device`,
    "Devices / named simulator representative",
    "partly",
    "The named device is visible; department membership remains a separate task.",
    groupRemedy,
    `${device.Hostname} represents the ${department} laptop in this synthetic walkthrough; it is not a newly enrolled native laptop.`,
  );
  await navigate(ctx, "Groups", "Device groups");
  await shot(
    ctx,
    `${id}-groups`,
    "Groups / create named membership",
    "partly",
    "Named members replace UUID entry, but group creation still sits among all saved group editors.",
    "Keep the new department and its membership review together without unrelated editors competing.",
    "No group has been saved yet.",
  );
  const name = `${department} ui-review ${id} ${randomUUID().slice(0, 8)}`;
  const form = formWithHeading(page, "Create group");
  await form.getByRole("textbox", { name: "Group name", exact: true }).fill(name);
  const members = form.getByRole("group", { name: "Member devices", exact: true });
  await members.getByRole("button", { name: "Add selection", exact: true }).click();
  await chooseNamed(ctx, members, "Member devices 1", device.Hostname, `${id}-member`);
  await form
    .getByRole("textbox", { name: "Group change reason", exact: true })
    .fill(
      `Isolated ${department} walkthrough group for ${device.Hostname}; preserve existing groups.`,
    );
  await shot(
    ctx,
    `${id}-group-members-populated`,
    "Groups / named membership review",
    "yes",
    "The selected hostname is visible instead of a raw identifier.",
    "Explain any existing account-access changes when editing a shared group.",
    `Only ${device.Hostname} is selected for this new isolated group; no existing group is changed.`,
  );
  await form.getByRole("button", { name: "Save group", exact: true }).click();
  const saved = formWithHeading(page, name);
  await visible(saved);
  await visible(
    saved.getByRole("button", { name: `Member devices 1 ${device.Hostname}`, exact: true }),
  );
  if ((await saved.getByRole("button", { name: /^Member devices \d+ / }).count()) !== 1)
    throw new Error("group_membership_not_saved");
  await shot(
    ctx,
    `${id}-group-saved`,
    "Groups / saved named membership",
    "yes",
    "The saved member remains human-readable; no copy-ID handoff is needed.",
    "Keep linked department tasks contextual; preserve named identity across destinations.",
    `The actual saved ${department} group shows exactly one named simulator member.`,
  );
  return { name };
}

async function onboard(ctx) {
  const { page } = ctx;
  const device = representative(ctx.config, "Engineering");
  await start(ctx, "onboard", "onboarding a laptop into Engineering");
  await navigate(ctx, "Enrollment", "Enroll a device");
  await shot(
    ctx,
    "onboard-method",
    "Enrollment / choose method",
    "partly",
    "Single-device and automatic enrollment are understandable, but neither carries an intended department or group into the task.",
    "Start with the new laptop and Engineering destination, then choose a one-time or installer enrollment method.",
    "One-device enrollment is selected for a laptop; no credential exists yet.",
  );
  await page.getByRole("button", { name: "Create one-time code", exact: true }).click();
  const form = page.getByRole("dialog", { name: "Enroll one device now", exact: true });
  await visible(form);
  await shot(
    ctx,
    "onboard-code-form",
    "Enrollment / one-time code dialog",
    "partly",
    "The form explains expiry but cannot bind the onboarding destination to Engineering.",
    "Show the intended Engineering destination alongside expiry and safe delivery.",
    "The visible dialog requests a reason before issuing a short-lived credential.",
  );
  await form
    .getByRole("textbox", { name: "Reason", exact: true })
    .fill("Onboard a new Engineering laptop; browser audit stops before native installation.");
  await shot(
    ctx,
    "onboard-code-review",
    "Enrollment / populated credential request",
    "partly",
    "The administrator reviews expiry and reason, but the new laptop's group placement is still a separate job.",
    "Include Engineering placement and the installer handoff in this review.",
    "A five-minute single-use credential is about to be created, not a device enrollment.",
  );
  await form.getByRole("button", { name: "Create one-time code", exact: true }).click();
  const result = page.getByRole("dialog", { name: "One-time enrollment code", exact: true });
  await visible(result);
  await shot(
    ctx,
    "onboard-credential-issued",
    "Enrollment / shown-once code",
    "partly",
    "The credential and installation handoff are task-oriented, but there is no joined destination or enrollment progress.",
    "Retain the safe shown-once handoff and connect it to Engineering membership and a waiting-for-first-check-in state.",
    "The credential result is displayed with all sensitive fields masked; its value is never read or copied by the audit.",
  );
  await result
    .getByText("Loading install command…", { exact: true })
    .waitFor({ state: "hidden", timeout });
  // An unavailable command is hidden and replaced by its blocking reason.
  const copyCommand = result.getByRole("button", { name: "Copy install command", exact: true });
  const blocked = result.getByRole("link", { name: /^Settings › Agent repository/ });
  await copyCommand.or(blocked).first().waitFor({ timeout });
  const instructionsAvailable = (await copyCommand.count()) === 1;
  await visible(
    instructionsAvailable
      ? result.getByRole("textbox", { name: "Install and enroll command", exact: true })
      : blocked,
  );
  await shot(
    ctx,
    "onboard-install-instructions",
    "Enrollment / installer instructions",
    "partly",
    "Installation requires a real terminal and may require installing the agent first; the browser cannot complete that prerequisite.",
    "Keep native installation requirements visible and provide a named pending-laptop checkpoint linked to group placement.",
    instructionsAvailable
      ? "Actual enrollment instructions are available. Running them on a new native laptop with the configured repository/trust is still required; no native enrollment is claimed."
      : "The credential was issued but installation instructions are unavailable; native onboarding is blocked here.",
  );
  await result.getByRole("button", { name: "Done, forget secret", exact: true }).click();
  await result.waitFor({ state: "hidden", timeout });
  await shot(
    ctx,
    "onboard-secret-dismissed",
    "Enrollment / credential history",
    "partly",
    "Closing the secret returns to credential history, not a new-laptop progress view.",
    "Show waiting for native enrollment and the intended Engineering destination without implying that issuing a code enrolled a laptop.",
    "Shown-once secret is dismissed. The audit has not delivered or consumed it.",
  );
  await createGroup(ctx, "onboard", "Engineering", device);
  return {
    outcome: "blocked",
    reason: `Enrollment credential ${instructionsAvailable ? "and instructions were" : "was"} issued through UI, and ${device.Hostname} was placed in an isolated Engineering group as a simulator representative. A real new laptop must install/run the agent and enroll before this job is complete; group membership does not prove native enrollment.`,
  };
}

async function baseline(ctx) {
  const { page } = ctx;
  const device = representative(ctx.config, "Finance");
  await start(ctx, "baseline", "rolling out a Finance baseline after reviewing affected devices");
  const group = await createGroup(ctx, "baseline", "Finance", device);
  await navigate(ctx, "Profiles", "Profiles");
  await shot(
    ctx,
    "baseline-profiles",
    "Profiles / catalog",
    "partly",
    "The catalog is separated from group selection and impact review.",
    rolloutRemedy,
    "A new isolated read-only encryption-compliance baseline will be authored; existing profiles are untouched.",
  );
  await page.getByRole("link", { name: "Create profile", exact: true }).click();
  await visible(page.getByRole("textbox", { name: "Name", exact: true }));
  await shot(
    ctx,
    "baseline-new-profile",
    "Profiles / create baseline",
    "partly",
    "A generic setting editor starts independently of Finance and its device capabilities.",
    rolloutRemedy,
    "New profile editor is open; no revision has been published.",
  );
  const profileName = `Finance baseline ui-review ${randomUUID().slice(0, 8)}`;
  await page.getByRole("textbox", { name: "Name", exact: true }).fill(profileName);
  await page
    .getByRole("textbox", { name: "Description", exact: true })
    .fill(
      "Isolated Finance audit baseline: report root-encryption compliance only; no disk or key changes.",
    );
  await page.getByRole("combobox", { name: "Setting type", exact: true }).click();
  await shot(
    ctx,
    "baseline-setting-options",
    "Profiles / setting choice",
    "partly",
    "The administrator chooses from a general-purpose setting catalog without Finance device context.",
    "Offer baseline goals with supported-device context and clear read-only versus modifying effects.",
    "The encryption-compliance setting is selected because it observes rather than encrypting disks.",
  );
  await page.getByRole("option", { name: "Encryption compliance", exact: true }).click();
  await page
    .getByRole("textbox", { name: "Reason", exact: true })
    .fill(
      "Review a new read-only Finance encryption baseline without changing native device policy.",
    );
  await shot(
    ctx,
    "baseline-profile-populated",
    "Profiles / populated baseline",
    "partly",
    "Publication has no Finance impact view; the operator must remember the eventual target.",
    rolloutRemedy,
    "The new baseline requires LUKS root-encryption reporting only; publishing is catalog-only, not activation.",
  );
  await page.getByRole("button", { name: "Publish profile", exact: true }).click();
  const revisionLink = page.getByRole("link", { name: "View this version", exact: true });
  await visible(revisionLink);
  await shot(
    ctx,
    "baseline-profile-published",
    "Profiles / published baseline",
    "partly",
    "Publication acknowledges a saved version but sends the operator to Rollouts without carrying its identity.",
    rolloutRemedy,
    "A new version is saved. No existing profile was edited, and no device has been activated.",
  );
  await navigate(ctx, "Rollouts", "Rollouts");
  await visible(page.getByRole("heading", { name: "Staged rollouts", exact: true }));
  await visible(page.getByRole("heading", { name: "Saved assignments", exact: true }));
  await shot(
    ctx,
    "baseline-rollouts",
    "Rollouts / staged rollouts and saved assignments",
    "yes",
    "Rollouts in progress and saved assignments lead the page; the new-rollout form waits behind its button.",
    "Owner should verify that existing assignments and stage controls stay visible without crowding the new rollout.",
    "No assignment has been saved; the new profile version remains catalog-only.",
  );
  await page.getByRole("button", { name: "New rollout", exact: true }).click();
  const proposal = page.getByRole("region", { name: "New rollout", exact: true });
  await visible(proposal);
  await chooseNamed(ctx, proposal, "Target", group.name, "baseline-cohort");
  await chooseNamed(ctx, proposal, "Profile", profileName, "baseline-profile-choice");
  await chooseNamed(ctx, proposal, "Version", `${profileName}, version 1`, "baseline-revision");
  await shot(
    ctx,
    "baseline-proposed-scope",
    "Rollouts / proposed Finance scope",
    "yes",
    "The proposal carries named Finance membership and the selected profile version.",
    "Keep review invalidation obvious when any target, revision, exclusion or timing input changes.",
    "Finance and the new read-only encryption-compliance baseline are selected; no assignment exists yet.",
  );
  await page.getByRole("button", { name: "Review affected devices", exact: true }).click();
  await visible(page.getByRole("heading", { name: "Affected devices", exact: true }));
  await visible(page.getByText(device.Hostname, { exact: true }).first());
  await shot(
    ctx,
    "baseline-before-save-impact",
    "Rollouts / proposed affected-device evidence",
    "yes",
    "The named device consequences are reviewed before assignment, with incomplete and unknown states retained.",
    "Owner should check reading order of differences/conflicts and distinguish catalog resolution from actual applied/native state.",
    "The actual server-generated proposed impact is visible before save. No client-side impact estimate or temporary assignment was used.",
  );
  const save = page.getByRole("button", { name: "Save reviewed assignment", exact: true });
  if (!(await save.isDisabled())) throw new Error("baseline_save_without_acknowledgement");
  await page
    .getByRole("textbox", { name: "Reason for this assignment", exact: true })
    .fill(
      "Assign the reviewed read-only Finance encryption-compliance baseline; native activation remains a separate reviewed action.",
    );
  await page
    .getByRole("checkbox", {
      name: "I reviewed the affected devices and consequences",
      exact: true,
    })
    .check();
  await shot(
    ctx,
    "baseline-reviewed-confirmation",
    "Rollouts / reviewed assignment confirmation",
    "yes",
    "The reason and acknowledgement follow visible named impact, not a generic confirmation dialog.",
    "Ensure incomplete/oversized/stale impact can never be accepted merely by checking the acknowledgement.",
    "The exact displayed proposal is acknowledged. Saving assignment is not activating or enforcing native settings.",
  );
  await save.click();
  await visible(
    page.getByText("Assignment saved. No device changes were activated.", { exact: true }),
  );
  await shot(
    ctx,
    "baseline-assignment-saved",
    "Rollouts / saved reviewed assignment",
    "yes",
    "The result distinguishes saved assignment from device activation.",
    "Keep the next authorized activation and its full combined-device effects explicit.",
    "The real save accepted the reviewed proposal; no native activation or policy execution is claimed.",
  );
  await visible(page.getByRole("heading", { name: "Staged rollouts", exact: true }));
  const staged = page.locator("article").filter({
    has: page.getByRole("heading", { name: "pilot, fleet", exact: true }),
  });
  await visible(
    staged.getByText(/^(Paused|Waiting to advance|Manual promotion required|Final stage)$/),
  );
  await staged.getByRole("combobox", { name: "Rollout decision", exact: true }).click();
  await visible(page.getByRole("option", { name: "Pause this rollout", exact: true }));
  await visible(page.getByRole("option", { name: "Resume this rollout", exact: true }));
  if (await page.getByRole("option", { name: /Advance to|Check promotion/ }).count()) {
    throw new Error("automatic_rollout_exposes_manual_advancement");
  }
  await shot(
    ctx,
    "baseline-staged-actions",
    "Rollouts / automatic-stage controls",
    "yes",
    "The automatic pilot exposes pause and resume, not a manual progress-check workaround.",
    "Only a manual ring with a following stage should offer administrator advancement.",
    "The actual automatic campaign has no manual advancement option. No rollout control is sent.",
  );
  await page.keyboard.press("Escape");
  await page.getByRole("option", { name: "Pause this rollout", exact: true }).waitFor({
    state: "hidden",
  });
  const draftReason = "Inspecting pilot health; no rollout change authorized in this walkthrough.";
  const reasonField = staged.getByRole("textbox", { name: "Reason for this change", exact: true });
  await reasonField.fill(draftReason);
  const observationStarted = Date.now();
  await page.waitForResponse(
    (response) =>
      response.url().endsWith("/lindm.admin.v1.AdminService/ListRollouts") &&
      response.status() === 200 &&
      Date.now() - observationStarted >= 9_000,
    { timeout: 30_000 },
  );
  if ((await reasonField.inputValue()) !== draftReason) {
    throw new Error("passive_rollout_refresh_replaced_unsent_draft");
  }
  await staged.getByText("Promotion evidence", { exact: true }).click();
  await visible(staged.getByText(/Across all stages reached:/));
  await visible(staged.getByText(/Stage started:/));
  await staged.scrollIntoViewIfNeeded();
  await shot(
    ctx,
    "baseline-staged-progress",
    "Rollouts / retained stage progress",
    "yes",
    "The stage state distinguishes waiting, paused, manual promotion and final-stage entry from completed device execution.",
    "Keep background advancement and current health evidence explicit; reading or refreshing must never promote a stage.",
    "The existing pilot/fleet campaign passively refreshed while preserving an unsent control draft. No promotion command, manual refresh or native-success claim was made.",
  );
  return {
    outcome: "completed",
    reason:
      "Created an isolated named Finance group and read-only baseline, reviewed actual proposed affected-device evidence before saving, and saved through the review-bound operation. Device activation and native enforcement remain separate tasks; this walk never activates unrelated existing seed policy.",
  };
}

async function helpdesk(ctx) {
  const { page } = ctx;
  const device = representative(ctx.config, "Engineering");
  await start(ctx, "helpdesk", "giving a new helpdesk hire limited Engineering access");
  const group = await createGroup(ctx, "helpdesk", "Engineering", device);
  await navigate(ctx, "Accounts", "Accounts");
  await shot(
    ctx,
    "helpdesk-accounts",
    "Accounts / create local account",
    "no",
    "The page lists accounts with role, device access and sign-in state; creation opens a dialog whose default role is admin and whose empty scope means all devices.",
    "Start an invite-helpdesk task with least-privilege role, required named scope, permission summary and a private enrollment handoff.",
    "No account has been created. The audit will explicitly choose helpdesk and Engineering rather than accept broad defaults.",
  );
  await page.getByRole("button", { name: "Create account", exact: true }).first().click();
  const createDialog = page.getByRole("dialog", { name: "Create account", exact: true });
  await visible(createDialog);
  const form = createDialog.locator("form");
  const username = `helpdesk-review-${randomUUID().slice(0, 8)}`;
  await form.getByRole("textbox", { name: "Username", exact: true }).fill(username);
  await form.getByRole("combobox", { name: "Role", exact: true }).click();
  await shot(
    ctx,
    "helpdesk-role-options",
    "Accounts / role choice",
    "no",
    "Role names are exposed without a permission or consequence summary for a new hire.",
    "Explain what helpdesk can do and cannot do before granting it; keep owner/admin grants clearly separate.",
    "The role choices are being inspected before creating any account.",
  );
  const option = page.getByRole("option", { name: "Helpdesk", exact: true });
  if (!(await option.isVisible())) {
    await page.keyboard.press("Escape");
    await shot(
      ctx,
      "helpdesk-role-blocked",
      "Accounts / missing helpdesk role",
      "no",
      "The required helpdesk role is not offered by this installation.",
      "Make the configured least-privilege helpdesk role available with a permission summary; never substitute admin.",
      "No account created: a configured helpdesk role is required.",
    );
    return {
      outcome: "blocked",
      reason:
        "The installation does not offer a helpdesk role. No broader role was substituted and no account was created.",
    };
  }
  await option.click();
  await form.getByRole("button", { name: "Add rule", exact: true }).click();
  await shot(
    ctx,
    "helpdesk-scope-rule",
    "Accounts / new device access rule",
    "partly",
    "Named choices replace ID lists, but any-rule scope semantics still require deliberate review.",
    "Show the chosen Engineering membership and effective access before creating the account.",
    "A scope rule exists but is not yet populated; account submission is withheld until its group is explicit.",
  );
  const groups = form.getByRole("group", { name: "Device groups", exact: true });
  await groups.getByRole("button", { name: "Add selection", exact: true }).click();
  await chooseNamed(ctx, groups, "Device groups 1", group.name, "helpdesk-scope");
  await shot(
    ctx,
    "helpdesk-access-review",
    "Accounts / populated limited access request",
    "partly",
    "Engineering is selected by name without copying identifiers; the effective-capability summary is still missing.",
    "Show Helpdesk — Engineering, member hostnames, allowed actions and excluded fleet scope in a final access review.",
    "Helpdesk role and exactly one Engineering group are populated; emergency-owner access is not selected.",
  );
  await form.getByRole("button", { name: "Create account", exact: true }).click();
  const secret = page.getByRole("region", { name: "One-time enrollment secret", exact: true });
  await visible(secret);
  await shot(
    ctx,
    "helpdesk-shown-once-handoff",
    "Accounts / private enrollment handoff",
    "partly",
    "The shown-once handoff explains private delivery, but it is separated from a named effective-access summary.",
    "Keep private handoff beside the hire's role and Engineering scope, and distinguish invited from enrolled.",
    "An actual account enrollment secret is shown and masked. The audit never reads, copies, downloads or persists it, and does not enroll the hire's browser identity.",
  );
  await secret.getByRole("button", { name: "Dismiss secret", exact: true }).click();
  await secret.waitFor({ state: "hidden", timeout });
  await shot(
    ctx,
    "helpdesk-secret-dismissed",
    "Accounts / handoff dismissed",
    "partly",
    "After dismissing the handoff, the operator returns to the account list without an effective-access summary for the hire.",
    "Keep the newly invited helpdesk hire selected with limited-access evidence and an explicit awaiting-user-setup state.",
    "The shown-once secret is gone; no credential material was retained by this scenario.",
  );
  // Reload through the normal route to assert persistence, not a mutation toast.
  await ctx.visit("/accounts");
  const row = page.getByRole("row").filter({ hasText: username });
  await visible(row);
  await visible(row.getByText("Waiting for setup", { exact: true }));
  await visible(row.getByText("Limited to 1 group", { exact: true }));
  await row.getByRole("button", { name: `Edit ${username}`, exact: true }).click();
  const editDialog = page.getByRole("dialog", { name: `Edit ${username}`, exact: true });
  await visible(editDialog);
  const saved = editDialog.locator("form");
  await visible(saved.getByRole("button", { name: `Device groups 1 ${group.name}`, exact: true }));
  const role = (
    await saved.getByRole("combobox", { name: "Role", exact: true }).innerText()
  ).trim();
  if (
    role !== "Helpdesk" ||
    (await saved.getByRole("button", { name: /^Device groups \d+ / }).count()) !== 1 ||
    (await saved.getByRole("button", { name: /^Devices \d+ / }).count()) !== 0 ||
    (await saved
      .getByRole("textbox", { name: "Labels (device must have all, one per line)", exact: true })
      .inputValue()) !== ""
  )
    throw new Error("helpdesk_access_not_persisted");
  if (
    !(await saved.getByRole("checkbox", { name: "Enabled", exact: true }).isChecked()) ||
    (await saved
      .getByRole("checkbox", { name: "Emergency (break-glass) owner", exact: true })
      .isChecked()) ||
    (await saved.getByRole("heading", { name: /^Rule \d+$/ }).count()) !== 1
  )
    throw new Error("helpdesk_access_scope_not_limited");
  await page.keyboard.press("Escape");
  await editDialog.waitFor({ state: "hidden", timeout });
  await shot(
    ctx,
    "helpdesk-persisted-access",
    "Accounts / saved limited account",
    "partly",
    "The persisted group is named rather than a UUID, but the account still lacks a compact effective-access summary.",
    "Show the hire, helpdesk capabilities, Engineering member devices and pending setup as one compact account record.",
    "After reload, the account row shows Helpdesk, Limited to 1 group and Waiting for setup, and its editor confirms the single Engineering group rule. This proves saved configuration, not a signed-in hire's authorization behavior.",
  );
  return {
    outcome: "completed",
    reason:
      "Created a local helpdesk account limited to an isolated Engineering group and verified its persisted role/scope and Waiting for setup state through UI. The one-time secret was masked and dismissed without retention. The real hire must receive a fresh privately delivered enrollment secret and complete their own password/authenticator setup; no real browser identity or signed-in authorization claim is made.",
  };
}

function journey(id, title, run) {
  return {
    id,
    title,
    run: async (ctx) => {
      try {
        return await run(ctx);
      } catch (error) {
        // Playwright call logs can include field values. Only fixed tokens may
        // leave this module; the parent captures the sanitized failure screen.
        const safe =
          error instanceof Error && error.message === "named_picker_matching_option_not_visible";
        throw new Error(safe ? error.message : `journey_${id}_ui_step_failed`);
      }
    },
  };
}

export const journeys = [
  journey("onboard", "Onboard a new laptop into Engineering", onboard),
  journey("baseline", "Roll out a new Finance baseline after seeing affected devices", baseline),
  journey("helpdesk", "Give a new helpdesk hire limited Engineering access", helpdesk),
];
