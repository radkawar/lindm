// SPDX-License-Identifier: Apache-2.0
import { openNavigationPage } from "./review-navigation.mjs";

// Whole-job UI evidence for the synthetic console fixture, not native qualification.
// Only this module's explicit UI requests mutate state. Never reveal a key, wipe,
// revoke a device, answer local consent, or call an RPC from these journeys.

async function visible(locator) {
  await locator.waitFor({ state: "visible", timeout: 15_000 });
}

function requireState(condition, token) {
  if (!condition) throw new Error(token);
}

async function settled(page) {
  await page.waitForFunction(
    () => {
      const main = document.querySelector("main");
      if (!main || main.querySelector('[aria-busy="true"]')) return false;
      return ![...main.querySelectorAll('[role="status"]')].some(
        (element) =>
          element.getClientRects().length && /^Loading\b/.test(element.textContent.trim()),
      );
    },
    undefined,
    { timeout: 15_000 },
  );
}

async function shot(ctx, name, screen, taskShaped, generic, remedy, outcome) {
  await settled(ctx.page);
  await ctx.capture(name, { screen, taskShaped, generic, remedy, outcome });
}

async function navigate(ctx, label) {
  await openNavigationPage(ctx.page, label);
}

async function start(ctx, job, destination) {
  await ctx.visit("/dashboard");
  await shot(
    ctx,
    `${job}-start`,
    "Dashboard",
    "partly",
    "The operator must translate the reported incident into a navigation destination.",
    "Offer named incident entry points while retaining fleet evidence and scope.",
    `Starting the ${job} job; no device effect has been requested.`,
  );
  await navigate(ctx, destination);
}

function routeDevice(config) {
  const device = config.demo.Devices.find((item) => item.ID === config.demo.Routes.DeviceID);
  requireState(device?.Hostname, "security_route_device_missing");
  return device;
}

async function findDevice(ctx, device, prefix) {
  const { page } = ctx;
  const main = page.getByRole("main");
  await visible(main.getByRole("heading", { name: "Devices", exact: true }));
  await shot(
    ctx,
    `${prefix}-device-search`,
    "Devices",
    "partly",
    "Hostname search is useful, but there is no incident-specific triage entry.",
    "Retain hostname and OS context; let an incident carry the chosen device forward.",
    "Searching the authorized fleet by the reported hostname, not by a pasted identifier.",
  );
  await main.getByRole("searchbox", { name: "Search devices" }).fill(device.Hostname);
  await shot(
    ctx,
    `${prefix}-search-populated`,
    "Devices search",
    "yes",
    "None.",
    "Preserve contextual hostname search.",
    "The reported hostname is entered; results have not been requested yet.",
  );
  await main.getByRole("button", { name: "Search", exact: true }).click();
  const row = main
    .getByRole("row")
    .filter({ has: page.getByRole("link", { name: device.Hostname, exact: true }) });
  await visible(row);
  await settled(page);
  requireState((await row.count()) === 1, "security_device_search_ambiguous");
  await shot(
    ctx,
    `${prefix}-search-result`,
    "Named device result",
    "yes",
    "None.",
    "Keep hostname, operating system, contact and enrollment context together.",
    "A single named matching row is visible with device context; enrollment is not health.",
  );
  await row.getByRole("link", { name: device.Hostname, exact: true }).click();
  await visible(main.getByRole("heading", { name: device.Hostname, exact: true }));
  await shot(
    ctx,
    `${prefix}-device-overview`,
    "Device overview",
    "partly",
    "Evidence is named, but the operator must assemble contact, access and the next incident action.",
    "Keep contact and encryption evidence beside the safe incident action and its limitations.",
    "The chosen device is open; observed state is not a new native verification.",
  );
}

async function openAction(ctx, label, prefix) {
  const main = ctx.page.getByRole("main");
  await main.getByRole("button", { name: "Actions", exact: true }).click();
  await visible(ctx.page.getByRole("menuitem", { name: label, exact: true }));
  await shot(
    ctx,
    `${prefix}-action-menu`,
    "Device actions menu",
    "partly",
    "The operator chooses among individual commands rather than an incident decision.",
    "Group safe incident actions by their purpose and preserve the selected device context.",
    "The action menu is open; no command has been sent.",
  );
  await ctx.page.getByRole("menuitem", { name: label, exact: true }).click();
  const dialog = ctx.page.getByRole("dialog", { name: label, exact: true });
  await visible(dialog);
  await visible(dialog.getByRole("button", { name: "Review action", exact: true }));
  await shot(
    ctx,
    `${prefix}-action-form`,
    label,
    "partly",
    "The form begins with command parameters, not an incident-specific decision.",
    "Lead with target, intended effect, timing and approval, then expose necessary choices.",
    "The action form is open, without changing the device.",
  );
  return dialog;
}

async function select(page, control, option) {
  await control.click();
  await page.getByRole("option", { name: option, exact: true }).click();
}

async function lostLaptop(ctx) {
  const { page, config } = ctx;
  // A non-route workstation is intentional: route-device assistance must remain usable.
  const device = config.demo.Devices.find(
    (item) =>
      item.ID !== config.demo.Routes.DeviceID &&
      item.State === "enrolled" &&
      /-ws-/.test(item.Hostname),
  );
  requireState(device, "lost_laptop_workstation_missing");
  await start(ctx, "lost-laptop", "Devices");
  await findDevice(ctx, device, "lost-laptop");
  const main = page.getByRole("main");
  await visible(main.getByRole("term").filter({ hasText: /^Last contact$/ }));
  await visible(main.getByText(/^(Root encrypted|Root not encrypted|Encryption unknown)$/));
  await main.getByRole("tab", { name: "Encryption", exact: true }).click();
  await visible(main.getByText(/^(Recoverable|Not recoverable|Unknown): /));
  await shot(
    ctx,
    "lost-laptop-encryption",
    "Device encryption evidence",
    "partly",
    "Encryption is split from the contact and lost-device decision; volumes use ordinal labels.",
    "Show root encryption, observation age and recoverability beside lost-device containment; name volumes by observed context.",
    "Reviewed reported encryption and key custody only. No recovery secret was revealed.",
  );
  const dialog = await openAction(ctx, "Lock sessions and local accounts", "lost-laptop");
  const existingLock = dialog.getByText("Undo the current account lock first.", { exact: true });
  if (await existingLock.isVisible()) {
    await shot(
      ctx,
      "lost-laptop-existing-lock",
      "Existing lock prerequisite",
      "partly",
      "A generic lock form cannot explain whether the existing restriction already addresses the incident.",
      "Link directly to the existing lock's target, effect and native evidence; never undo containment just to request it again.",
      "A current account lock blocks a new request. Existing restrictions were not altered.",
    );
    return {
      outcome: "blocked",
      reason:
        "The selected workstation already has an account lock. Its existing action needs review; native confirmation is required before claiming containment.",
    };
  }
  await select(
    page,
    dialog.getByRole("combobox", { name: "Block local sign-in" }),
    "All local user accounts",
  );
  const reason =
    "Lost laptop reported by its user; lock sessions and block local logins pending incident review.";
  await dialog.getByRole("textbox", { name: "Reason", exact: true }).fill(reason);
  await shot(
    ctx,
    "lost-laptop-form-populated",
    "Lost laptop lock choices",
    "partly",
    "The operator must infer the containment boundary and its reversibility from technical choices.",
    "Explain that session/account lock is not wipe, not network isolation and cannot prove an offline laptop is protected.",
    "Selected lock without sign-out and all eligible local accounts; requesting independent review, not immediate execution.",
  );
  await dialog.getByRole("button", { name: "Review action", exact: true }).click();
  // The review runs the server's checks; stale demo inventory honestly blocks Send.
  await visible(dialog.getByText(/^(Ready to send|Not ready to send)$/));
  await visible(dialog.getByText(device.Hostname, { exact: true }));
  await visible(dialog.getByText("No: lock only", { exact: true }));
  await visible(dialog.getByText("All eligible local human accounts", { exact: true }));
  await visible(dialog.getByText("Root and the device's protected accounts", { exact: true }));
  await shot(
    ctx,
    "lost-laptop-impact",
    "Lock impact and approval review",
    "no",
    "The review says 'Check the details above before sending' and 'Approval: Not requested'; it does not explain the approval requirement, timing or undo path.",
    "Show one named device, affected sessions/accounts, protected exclusions, check-in dependency, account-unlock remedy and whether independent approval is required.",
    "Exact reviewed payload locks sessions without sign-out and disables eligible local human accounts. It does not erase data or revoke enrollment.",
  );
  const requestApproval = dialog.getByRole("button", { name: "Request approval", exact: true });
  if (await dialog.getByText("Not ready to send", { exact: true }).isVisible()) {
    // The server admits a device action only while the device is in contact
    // (an online preflight, not an offline queue), and the review checks it
    // before an approval is requested. Demo workstations stop reporting.
    requireState(await requestApproval.isDisabled(), "lost_laptop_unready_approval_offered");
    const blocker = dialog.locator('[data-slot="action-blocker"]');
    await visible(blocker);
    const blockerTitle = (await blocker.locator('[data-slot="alert-title"]').innerText()).trim();
    requireState(blockerTitle.length > 0, "lost_laptop_refusal_reason_missing");
    await visible(
      dialog.getByText(
        `Send and approval requests are unavailable. Resolve this problem: ${blockerTitle.toLowerCase()}.`,
        { exact: true },
      ),
    );
    await shot(
      ctx,
      "lost-laptop-refused",
      "Lock refused by the server's checks",
      "partly",
      "The refusal names its cause and remedy, but a lost laptop is usually offline: the lock cannot be queued for its next check-in.",
      "Say what the administrator can do while the laptop stays offline, and offer to act when it next checks in.",
      "The server's checks refused the lock before any approval was requested. Nothing was sent; the device is unchanged.",
    );
    await dialog.getByRole("button", { name: "Edit action", exact: true }).click();
    await page.keyboard.press("Escape");
    await dialog.waitFor({ state: "hidden", timeout: 15_000 });
    return {
      outcome: "blocked",
      reason:
        "The lock review ran the server's checks, which refused the request with its named cause (the synthetic workstation is not in contact), so no approval was requested and nothing was sent. lindm acts only on devices in recent contact; containing an offline lost laptop waits for it to reconnect.",
    };
  }
  await requestApproval.click();
  await visible(dialog.getByText("Waiting for approval", { exact: true }));
  await shot(
    ctx,
    "lost-laptop-approval-pending",
    "Lock approval pending",
    "partly",
    "The command form remains the primary surface after the approval request.",
    "Lead with the named pending containment request, next approver and the fact that no lock has executed.",
    "Approval was requested. This single administrator has not approved or sent the lock action.",
  );
  await dialog.getByRole("link", { name: "Open approvals", exact: true }).click();
  await visible(main.getByRole("heading", { name: "Approval inbox", exact: true }));
  await visible(main.getByText(reason, { exact: true }));
  await main.getByText(reason, { exact: true }).scrollIntoViewIfNeeded();
  await shot(
    ctx,
    "lost-laptop-approval-record",
    "Approval queue",
    "partly",
    "The operator changes screens to track an incident request rather than staying in a containment workflow.",
    "Keep the incident target, requested restriction and next independent decision together.",
    "The submitted reason appears in the real approval queue. No fixture device was wiped, revoked or locked by this journey.",
  );
  return {
    outcome: "blocked",
    reason:
      "Lock request awaits an independent second administrator. After approval and explicit execution, device contact and native lock evidence are still required; approval is not containment.",
  };
}

async function criticalCVE(ctx) {
  const { page, config } = ctx;
  const main = page.getByRole("main");
  await start(ctx, "critical-cve", "Advisories");
  await visible(main.getByRole("heading", { name: "Advisories", exact: true }));
  await visible(main.getByRole("heading", { name: "Advisory sources", exact: true }));
  await settled(page);
  const criticalRows = main
    .getByRole("row")
    .filter({ has: page.getByRole("cell", { name: "Critical", exact: true }) });
  const criticalCount = await criticalRows.count();
  await shot(
    ctx,
    "critical-cve-coverage",
    "Fleet advisory coverage",
    "no",
    "Advisory counts and severities have no exposed-device drilldown or critical-CVE search; unchecked devices are a separate total.",
    "Make each advisory open named affected devices and place source/inventory gaps beside that scoped exposure.",
    criticalCount
      ? "Critical severity rows exist on this page; their counts do not identify or prove a particular exposed device."
      : "No Critical severity row is visible on this page. This is not proof of no critical exposure across the fleet.",
  );
  // One page Refresh rereads the advisory summary and the sources.
  await main.getByRole("button", { name: "Refresh", exact: true }).click();
  await settled(page);
  await main
    .getByRole("heading", { name: "Advisory sources", exact: true })
    .scrollIntoViewIfNeeded();
  await shot(
    ctx,
    "critical-cve-sources",
    "Advisory source freshness",
    "partly",
    "Refresh reloads source status; remediation may require server configuration or native inventory work outside this screen.",
    "Connect missing, rejected or stale source coverage to named affected scopes and an actionable refresh/setup remedy.",
    "Reloaded source status through the UI; source freshness alone cannot establish complete exposure coverage.",
  );
  const skipped = main.getByRole("region", { name: "Skipped entries", exact: true });
  for (let index = 0; index < (await skipped.count()); index += 1) {
    await skipped.nth(index).scrollIntoViewIfNeeded();
    await shot(
      ctx,
      `critical-cve-source-rejections-${index + 1}`,
      "Rejected advisory source records",
      "partly",
      "Skipped records require manual interpretation to determine which devices cannot be evaluated.",
      "Link rejected package coverage to affected named devices; retain Unknown rather than reassuring zeros.",
      "Inspected the reported rejected records; an unreadable advisory is not an unaffected package.",
    );
  }
  await main.getByRole("link", { name: "View findings by device", exact: true }).click();
  // This is the actual current detour: the advisory table has no target link.
  // After an advisory-to-device picker/drilldown lands, replace this manual named
  // device traversal with that UI, not a raw-ID fallback or direct findings URL.
  const devices = config.demo.Devices.filter(
    (item) => item.Hostname && ["enrolled", "stale"].includes(item.State),
  );
  requireState(devices.length > 0, "critical_cve_devices_missing");
  let exposed;
  for (let index = 0; index < devices.length; index += 1) {
    if (index) await navigate(ctx, "Devices");
    const device = devices[index];
    await findDevice(ctx, device, `critical-cve-${index + 1}`);
    await main.getByRole("tab", { name: "Findings", exact: true }).click();
    await visible(main.getByRole("heading", { name: "Security findings", exact: true }));
    await settled(page);
    // Findings are table rows, most severe first.
    const criticalAffected = main
      .getByRole("tabpanel", { name: "Findings", exact: true })
      .getByRole("table", { name: "Security findings on this device", exact: true })
      .getByRole("row")
      .filter({ has: page.getByRole("cell", { name: "Critical", exact: true }) })
      .filter({ has: page.getByText(/^Affected(?: \(acceptance expired\))?$/) });
    const currentCritical = (await criticalAffected.count()) > 0;
    if (currentCritical && !exposed) exposed = device;
    await shot(
      ctx,
      `critical-cve-${index + 1}-findings`,
      "Named device findings",
      "partly",
      "Finding rows offer risk acceptance but no contextual patch action or fleet exposure drilldown.",
      "Offer patch review from a current affected finding, retaining CVE, package, fixed version and evidence freshness.",
      currentCritical
        ? "This named device has a visible current Affected finding explicitly marked Critical. It remains synthetic fixture evidence."
        : "This device has no visible current Affected finding explicitly marked Critical on this page. Unknown, accepted, stale and absent findings are not asserted safe.",
    );
  }
  const target = exposed ?? routeDevice(config);
  await navigate(ctx, "Devices");
  await findDevice(ctx, target, "critical-cve-patch-target");
  const dialog = await openAction(ctx, "Patch now", "critical-cve");
  await dialog
    .getByRole("textbox", { name: "Reason", exact: true })
    .fill(
      exposed
        ? "Review security updates for the critical affected finding shown on this device."
        : "Review the security update path only; critical exposure is not established by current UI evidence.",
    );
  await shot(
    ctx,
    "critical-cve-patch-populated",
    "Patch-now choices",
    "partly",
    "The generic patch form is disconnected from the advisory/package that motivated the work.",
    "Carry finding and named-device context into security-update and reboot impact review.",
    "Security-only updates and no automatic reboot are the displayed defaults. No patch has been requested yet.",
  );
  await dialog.getByRole("button", { name: "Review action", exact: true }).click();
  await visible(dialog.getByText(/^(Ready to send|Not ready to send)$/));
  const sendable = await dialog.getByText("Ready to send", { exact: true }).isVisible();
  await visible(dialog.getByText("Security updates", { exact: true }));
  await visible(dialog.getByText("Never: report reboot-required only", { exact: true }));
  await visible(dialog.getByText(/The action confirms only that the native update run started/));
  await shot(
    ctx,
    "critical-cve-patch-impact",
    "Patch impact review",
    "partly",
    "The review explains service disruption and evidence limits but does not preview packages or prove the selected CVE has an available fix.",
    "Show available native package changes and advisory linkage, retaining unknowns and separate run/compliance evidence.",
    exposed
      ? "A critical affected device is selected. The request can start native updating; accepting it cannot prove remediation."
      : "Coverage blocker: no inspected device has a current Critical affected finding. The patch workflow is reviewed, not misrepresented as CVE remediation.",
  );
  if (exposed && sendable) {
    await dialog.getByRole("button", { name: "Send action", exact: true }).click();
    await visible(main.getByRole("heading", { name: "Patch now", exact: true }));
    await visible(main.getByRole("article"));
    await visible(
      main
        .getByRole("article")
        .getByText(
          /^(Sent, waiting for device|No result yet|Prepared, not started|Queued|Running|Completed|Failed|Outcome unknown, don't retry|Expired)$/,
          { exact: true },
        ),
    );
    await shot(
      ctx,
      "critical-cve-patch-result",
      "Patch request result",
      "partly",
      "Action status and installed-update evidence live on separate screens.",
      "Link the exact patch request to its native run, installed package versions and refreshed CVE finding.",
      "The server accepted the patch request and displays its recorded status. This does not prove packages changed or the CVE was fixed.",
    );
    await main
      .getByRole("link", { name: /^Back to / })
      .first()
      .click();
  } else {
    await dialog.getByRole("button", { name: "Edit action", exact: true }).click();
    await page.keyboard.press("Escape");
  }
  await main.getByRole("tab", { name: "Inventory", exact: true }).click();
  await visible(main.getByText("Patch status", { exact: true }));
  await shot(
    ctx,
    "critical-cve-native-evidence",
    "Native patch observation",
    "partly",
    "Inventory's patch status is disconnected from the incident and may predate this request.",
    "Correlate the request and timestamp with native run result, package inventory and reevaluated findings before reporting fixed.",
    exposed && sendable
      ? "Inspected reported patch evidence after the request; no native execution or CVE remediation is claimed."
      : exposed
        ? "Inspected available patch evidence; no update was sent because the server's review checks refused the request."
        : "Inspected available patch evidence; no update was sent because the critical exposure prerequisite was not established.",
  );
  return {
    outcome: "blocked",
    reason:
      exposed && sendable
        ? "A security update request was accepted for a device with visible Critical affected evidence. The synthetic fixture cannot prove a native patch run or remediation; fresh package inventory and reevaluated findings are required."
        : exposed
          ? "A device with visible Critical affected evidence was found, but the review's server checks refused the patch request (shown with its remedy); nothing was sent."
          : "No current Critical affected finding was established on the inspected fixture-device pages. Fleet advisories lack exposed-device drilldown/search; source and inventory gaps cannot be treated as safety. Patch review was completed without sending an unjustified remediation request.",
  };
}

async function remoteHelp(ctx) {
  const { page, config } = ctx;
  const device = routeDevice(config);
  const main = page.getByRole("main");
  await start(ctx, "remote-help", "Devices");
  await findDevice(ctx, device, "remote-help");
  await main.getByRole("tab", { name: "Remote assistance", exact: true }).click();
  await visible(main.getByRole("heading", { name: "Ask to help", exact: true }));
  await shot(
    ctx,
    "remote-help-request-entry",
    "Device assistance request",
    "partly",
    "Remote help has its own device tab, but is not yet offered beside the signed-in user's session context.",
    "Provide an Ask to help action beside user/session context, preserving consent and history.",
    "Opened the real remote assistance form on the named, checking-in route device.",
  );
  const reason =
    "Help the user diagnose a frozen application; please share your screen only if you consent.";
  await main
    .getByRole("textbox", {
      name: "Reason (the user sees this; the audit log records it)",
      exact: true,
    })
    .fill(reason);
  await select(
    page,
    main.getByRole("combobox", { name: "Mode", exact: true }),
    "View and request control",
  );
  await main
    .getByRole("spinbutton", { name: "Maximum duration (minutes, 1 to 30)", exact: true })
    .fill("5");
  await shot(
    ctx,
    "remote-help-reason-and-consent",
    "Populated support request",
    "yes",
    "None in the request itself.",
    "Keep the user-visible reason, requested access, duration and consent impact together.",
    "Requested five minutes of view-and-request-control access. The user may choose view-only or decline; requesting does not share a screen.",
  );
  let requested = false;
  try {
    await main.getByRole("button", { name: "Request remote assistance", exact: true }).click();
    requested = true;
    await visible(main.getByRole("heading", { name: "Remote assistance", exact: true }));
    await visible(main.getByRole("button", { name: "Stop session", exact: true }));
    await visible(
      main.getByText(
        "The device shares no screen or input yet. Wait for user consent, or stop the request.",
        { exact: true },
      ),
    );
    await visible(main.getByText(reason, { exact: true }));
    const takeControl = main.getByRole("button", { name: "Take control", exact: true });
    await visible(takeControl);
    requireState(await takeControl.isDisabled(), "remote_help_control_before_consent");
    const explanation = await takeControl.getAttribute("aria-describedby");
    requireState(explanation, "remote_help_control_reason_missing");
    for (const id of explanation.split(/\s+/))
      await visible(page.locator(`[id=${JSON.stringify(id)}]`));
    await shot(
      ctx,
      "remote-help-waiting-for-user",
      "Waiting for local consent",
      "yes",
      "None in the consent boundary.",
      "Preserve the explicit no-sharing state, disabled control explanation and prominent stop action.",
      "The real session is waiting for the person on the device. No consent, live screen or input transport was simulated.",
    );
    await main.getByRole("button", { name: "Stop session", exact: true }).click();
    await visible(main.getByRole("heading", { name: "Why this session ended", exact: true }));
    // No one accepted, so the record says nothing was shared (a started session
    // reads "Session record. Sharing and control have ended.").
    await visible(main.getByText("Request record. The device shared nothing.", { exact: true }));
    requireState(!(await takeControl.isVisible()), "remote_help_ended_control_visible");
    requested = false;
    await shot(
      ctx,
      "remote-help-ended",
      "Ended assistance record",
      "yes",
      "None in the ended-state boundary.",
      "Keep end cause/time, historical permissions and return-to-device action; never imply historical consent grants access.",
      "Stopped this journey's request through the UI and observed its ended record. A real local user and native desktop are required to continue actual support.",
    );
    await visible(main.getByText(reason, { exact: true }));
    await main
      .locator("summary")
      .filter({ hasText: /^Details$/ })
      .click();
    await shot(
      ctx,
      "remote-help-ended-details",
      "Historical support request",
      "yes",
      "None.",
      "Preserve the reason and requested/start timestamps as history, not current access.",
      "The ended record retains the supplied support reason without granting new sharing permission.",
    );
    await main.getByRole("link", { name: "Return to device", exact: true }).click();
    await main.getByRole("tab", { name: "Remote assistance", exact: true }).click();
    await visible(main.getByRole("heading", { name: "Session history", exact: true }));
    await shot(
      ctx,
      "remote-help-history",
      "Device assistance history",
      "partly",
      "Session history is separated from the device user's immediate support context.",
      "Make the latest ended request easy to resume as a new request requiring fresh consent.",
      "Returned to the device's real session history. This journey leaves no active assistance session.",
    );
  } finally {
    // Even a capture/assertion failure must not leave our request blocking the
    // parent's later assistance review. Never stop pre-existing history entries.
    if (requested) {
      const stop = main.getByRole("button", { name: "Stop session", exact: true });
      if (await stop.isVisible()) {
        await stop.click();
        await visible(main.getByRole("heading", { name: "Why this session ended", exact: true }));
      } else {
        // Creator navigation uses the product's stop-on-leave behavior. This is
        // only the error path; normal completion asserts the explicit ended UI.
        await ctx.visit("/devices");
      }
    }
  }
  return {
    outcome: "blocked",
    reason:
      "Requested support, observed explicit consent waiting, stopped the request and reviewed its ended record. Actual help requires a consenting local person and a native desktop/transport; neither was fabricated.",
  };
}

async function recoveryAudit(ctx) {
  const { page } = ctx;
  const main = page.getByRole("main");
  await start(ctx, "recovery-audit", "Audit log");
  await visible(main.getByRole("heading", { name: "Audit log", exact: true }));
  await shot(
    ctx,
    "recovery-audit-entry",
    "Audit / investigation choices",
    "yes",
    "The log offers named investigation views instead of requiring action codes.",
    "Owner should edit the order and wording of the common investigation choices.",
    "No recovery or time filter has been applied yet; the default Human actions view is not the answer.",
  );
  await main.getByRole("button", { name: "Recovery key reveals", exact: true }).click();
  await shot(
    ctx,
    "recovery-audit-reveal-view",
    "Audit / recovery-key reveals",
    "yes",
    "The event category is a named choice; identifiers remain diagnostic context.",
    "Keep the category visible while composing actor, device and time scope.",
    "The recovery-key-reveal quick view is selected; the date range is still explicit and separate.",
  );
  await main.getByRole("combobox", { name: "Time range", exact: true }).click();
  await page
    .getByRole("option", { name: "Last week, Monday to Sunday (UTC)", exact: true })
    .click();
  await settled(page);
  // The chosen week is saved as fixed UTC dates in the URL.
  await page.waitForURL(
    /[?&]from=\d{4}-\d{2}-\d{2}.*[?&]through=\d{4}-\d{2}-\d{2}|[?&]through=\d{4}-\d{2}-\d{2}.*[?&]from=\d{4}-\d{2}-\d{2}/,
    {
      timeout: 15_000,
    },
  );
  const saved = () => new URL(page.url()).searchParams;
  const from = saved().get("from") ?? "";
  const through = saved().get("through") ?? "";
  requireState(
    /^\d{4}-\d{2}-\d{2}$/.test(from) &&
      /^\d{4}-\d{2}-\d{2}$/.test(through) &&
      Date.parse(`${through}T00:00:00Z`) - Date.parse(`${from}T00:00:00Z`) === 6 * 86400000,
    "recovery_audit_calendar_week_missing",
  );
  const rows = main.getByRole("row").filter({ has: page.getByRole("cell") });
  const resultCount = await rows.count();
  if (resultCount === 0) {
    await visible(main.getByText("No matching events", { exact: true }));
  } else {
    for (const row of await rows.all()) {
      requireState(
        (await row.getByRole("cell").nth(1).innerText()).trim().startsWith("Revealed recovery key"),
        "recovery_audit_wrong_action_category",
      );
    }
  }
  await shot(
    ctx,
    "recovery-audit-last-week-answer",
    "Audit / dated reveal-history answer",
    "yes",
    "The fixed UTC range, named actors and scoped empty state answer a bounded question.",
    "Owner should check clarity of unavailable historical names and event context; never substitute a current name for proof of historical identity.",
    resultCount === 0
      ? `The actual UI reports no matching recorded recovery-key reveals from ${from} through ${through}, UTC. This is not a claim about events outside that range.`
      : `The first filtered page contains ${resultCount} recorded recovery-key reveal events for ${from} through ${through}, UTC; remaining pages, if any, are not silently counted as reviewed.`,
  );
  await page.reload();
  await visible(main.getByRole("heading", { name: "Audit log", exact: true }));
  await settled(page);
  requireState(
    saved().get("from") === from &&
      saved().get("through") === through &&
      (await main.getByRole("combobox", { name: "Time range", exact: true }).innerText()).includes(
        "Last week",
      ) &&
      (await main
        .getByRole("button", { name: "Recovery key reveals", exact: true })
        .getAttribute("aria-pressed")) === "true",
    "recovery_audit_bookmark_scope_changed",
  );
  await shot(
    ctx,
    "recovery-audit-bookmark",
    "Audit / restored dated view",
    "yes",
    "The URL retains fixed dates rather than silently advancing a relative last-week bookmark.",
    "Keep the visible dates and timezone beside restored views.",
    "Reloading the actual bookmarked route preserves the recovery-reveal category and exact UTC dates.",
  );
  const hostname = routeDevice(ctx.config).Hostname;
  for (const choice of [
    { label: "Actor", name: "console-owner", slug: "actor" },
    { label: "Device", name: hostname, slug: "device" },
  ]) {
    await main.getByRole("button", { name: new RegExp(`^${choice.label} `) }).click();
    // The picker's choices float in a popover outside main.
    await page
      .getByRole("combobox", { name: `Search ${choice.label.toLowerCase()}`, exact: true })
      .fill(choice.name);
    const option = page.getByRole("option", { name: choice.name, exact: true });
    await visible(option);
    await shot(
      ctx,
      `recovery-audit-${choice.slug}-choices`,
      `Audit / named ${choice.slug} choice`,
      "yes",
      "The selection comes from audit-authorized named results, not a pasted identifier.",
      "Owner should check name disambiguation when several recorded entities share a display name.",
      `The actual picker finds ${choice.name}; no hidden account/device RPC or invented identifier is used.`,
    );
    await option.click();
    await shot(
      ctx,
      `recovery-audit-${choice.slug}-selected`,
      `Audit / composed ${choice.slug} filter`,
      "yes",
      "The selected name remains visible alongside the category and time scope.",
      "Preserve unavailable saved selections explicitly; never clear a filter silently.",
      `The investigation is additionally narrowed to ${choice.name}; the original all-actor answer above remains distinct.`,
    );
  }
  await main.getByRole("button", { name: "Export filtered evidence", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Export filtered evidence", exact: true });
  await visible(dialog);
  await visible(
    dialog.getByText("This signed selection is not a complete audit chain.", { exact: false }),
  );
  await shot(
    ctx,
    "recovery-audit-export-scope",
    "Audit / exact export scope",
    "yes",
    "The dialog carries named scope and dates, not sequence/hash protocol fields.",
    "Keep selection versus complete-chain integrity explicit without asking operators to construct checkpoints.",
    `Export review shows the recovery-reveal selection for ${from} through ${through}, UTC, narrowed to the chosen actor and device.`,
  );
  await dialog
    .getByRole("textbox", { name: "Reason for export", exact: true })
    .fill(
      "Investigate recorded recovery-key reveals during the displayed previous calendar week for this named actor and device.",
    );
  await shot(
    ctx,
    "recovery-audit-export-reason",
    "Audit / reasoned export request",
    "yes",
    "The reason is attached to an already-visible selection, not a generic report form.",
    "Keep limits, retention and the exact selected scope visible before submission.",
    "The export reason is entered; no report has been requested yet.",
  );
  await dialog.getByRole("button", { name: "Start export", exact: true }).click();
  await visible(dialog.getByText("Export queued for the scope above.", { exact: true }));
  await shot(
    ctx,
    "recovery-audit-export-queued",
    "Audit / queued evidence",
    "yes",
    "The next action leads to this report; queue acceptance is not presented as a completed download.",
    "Keep the selected investigation context visible when moving to its report.",
    "The real server accepted the selected export request; publication is not yet claimed.",
  );
  await dialog
    .getByRole("link", { name: "View export and download evidence", exact: true })
    .click();
  await visible(main.getByRole("heading", { name: "Integrations and reports", exact: true }));
  const anchor = new URL(page.url()).hash;
  requireState(/^#report-[0-9a-f-]{36}$/i.test(anchor), "recovery_audit_report_link_missing");
  const artifact = page.locator(anchor);
  await visible(artifact);
  await artifact.scrollIntoViewIfNeeded();
  await shot(
    ctx,
    "recovery-audit-report-status",
    "Reports / selected evidence status",
    "partly",
    "The export is named correctly, but its completion still sits among unrelated integration tools.",
    "Owner may prefer an in-context report completion panel linked back to the exact audit view.",
    "The product's own report link identifies the queued artifact; no report identifier was entered by the administrator.",
  );
  const deadline = Date.now() + 45_000;
  while (!(await artifact.getByText("Published", { exact: true }).isVisible())) {
    requireState(
      !(await artifact.getByText("Failed", { exact: true }).isVisible()),
      "recovery_audit_export_failed",
    );
    requireState(Date.now() < deadline, "recovery_audit_export_publication_timeout");
    await main.getByRole("button", { name: "Refresh", exact: true }).click();
    await settled(page);
    // Deadline-bounded polling of the actual refresh control, not a mutation retry.
    if (!(await artifact.getByText("Published", { exact: true }).isVisible()))
      await page.waitForTimeout(500);
  }
  await artifact.scrollIntoViewIfNeeded();
  await shot(
    ctx,
    "recovery-audit-report-published",
    "Reports / signed evidence available",
    "yes",
    "Publication and enabled downloads are actual server state, not a queued-success toast.",
    "Keep filtered selections distinct from complete-chain checkpoints in every report entry point.",
    "The actual selected report is published and its evidence/signature downloads are enabled.",
  );
  for (const label of ["Download", "Download signature"]) {
    const arriving = page.waitForEvent("download");
    await artifact.getByRole("button", { name: label, exact: true }).click();
    const download = await arriving;
    requireState((await download.failure()) === null, "recovery_audit_download_failed");
    await shot(
      ctx,
      `recovery-audit-${label === "Download" ? "evidence" : "signature"}-download`,
      `Reports / ${label.toLowerCase()}`,
      "yes",
      "Evidence and its signature are separate explicit downloads.",
      "Owner should check whether paired download wording is clear; a signature file alone is not verification.",
      `${label} completed through the real browser UI. The task runner did not read report bodies, reveal keys or retain the browser's temporary download.`,
    );
  }
  return {
    outcome: "completed",
    reason: `Answered the recovery-reveal question for ${from} through ${through}, UTC, restored its fixed-date bookmark, composed named actor/device scope, and downloaded the actual published filtered evidence and signature. No recovery secret was revealed; browser download success is not a cryptographic verification claim.`,
  };
}

// Keep browser diagnostics out of audit errors: Playwright failures can contain
// complete locators/page snippets. Screenshots are sanitized by the parent.
export const journeys = [
  { id: "lost-laptop", title: "Contain a user's lost laptop", run: lostLaptop },
  { id: "critical-cve", title: "Investigate and patch a critical CVE", run: criticalCVE },
  { id: "remote-help", title: "Ask to help a user, then stop the request", run: remoteHelp },
  { id: "recovery-audit", title: "Find who revealed a recovery key last week", run: recoveryAudit },
].map((journey) => ({
  ...journey,
  run: async (ctx) => {
    try {
      return await journey.run(ctx);
    } catch (error) {
      const token =
        error instanceof Error && /^[a-z][a-z0-9_]+$/.test(error.message)
          ? error.message
          : `${journey.id.replaceAll("-", "_")}_ui_step_failed`;
      throw new Error(token);
    }
  },
}));
