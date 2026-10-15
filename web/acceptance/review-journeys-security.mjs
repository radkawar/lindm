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
  await visible(
    main.getByRole("button", { name: "Recovery key reveals", exact: true, pressed: true }),
  );
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
  // The chosen week is saved as fixed UTC dates in the URL.
  await page.waitForURL(
    /[?&]from=\d{4}-\d{2}-\d{2}.*[?&]through=\d{4}-\d{2}-\d{2}|[?&]through=\d{4}-\d{2}-\d{2}.*[?&]from=\d{4}-\d{2}-\d{2}/,
    {
      timeout: 15_000,
    },
  );
  // URL navigation can finish before React commits the new filter. Do not
  // inspect rows from the previous scope while its replacement is still loading.
  await visible(
    main
      .getByRole("combobox", { name: "Time range", exact: true })
      .filter({ hasText: "Last week, Monday to Sunday (UTC)" }),
  );
  await settled(page);
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
  const device = ctx.config.demo?.Devices?.find(
    (entry) => entry.ID === ctx.config.demo?.Routes?.DeviceID,
  );
  requireState(device?.Hostname, "recovery_audit_device_missing");
  const hostname = device.Hostname;
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
