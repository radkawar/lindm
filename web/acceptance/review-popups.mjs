// Popup stability for `lab console review`: opening a dropdown, picker, menu or
// popover must float over the page, never move the page's content. Each visible
// popup trigger on the captured state is opened with real input; on-screen boxes
// of the main content are compared before and while it is open. A scroll lock
// that drops the scrollbar, or a picker that expands inline, moves them. (A lock
// may move scrolling from the window to <body>; only what the user sees counts.)
// Expanding buttons without aria-haspopup count when they reveal choices (a
// listbox, menu or command list); plain disclosures may move content.

const maxTriggers = 16;
const tolerancePx = 1;

function markTriggers(limit) {
  // checkVisibility also excludes content of closed <details> (content-visibility).
  const visible = (node) => {
    const rect = node.getBoundingClientRect();
    return (
      rect.width > 0 &&
      rect.height > 0 &&
      node.checkVisibility({ contentVisibilityAuto: true, visibilityProperty: true })
    );
  };
  for (const node of document.querySelectorAll("[data-review-popup]"))
    node.removeAttribute("data-review-popup");
  const triggers = [
    ...document.querySelectorAll(
      '[aria-haspopup]:not([aria-haspopup="false"]),button[aria-expanded="false"]',
    ),
  ].filter(
    (node) =>
      visible(node) &&
      !node.disabled &&
      node.getAttribute("aria-disabled") !== "true" &&
      !node.closest('[role="dialog"],[role="alertdialog"],[role="menu"],[role="listbox"]'),
  );
  return triggers.slice(0, limit).map((node, index) => {
    node.setAttribute("data-review-popup", String(index));
    const name = (node.getAttribute("aria-label") ?? node.innerText ?? "").replace(/\s+/g, " ");
    const popup = node.hasAttribute("aria-haspopup")
      ? `aria-haspopup=${node.getAttribute("aria-haspopup")}`
      : "aria-expanded";
    return `${node.tagName.toLowerCase()}[${popup}] "${name.trim().slice(0, 60)}"`;
  });
}

// Choices revealed by an expanding button without aria-haspopup.
function revealsChoices() {
  return [...document.querySelectorAll('[role="listbox"],[role="menu"],[cmdk-list]')].some(
    (node) => node.getClientRects().length > 0,
  );
}

function measure() {
  const main = document.querySelector("main") ?? document.body;
  const nodes = [
    main,
    ...main.querySelectorAll(
      'h1,h2,h3,table,form,section,[data-slot="card"],[data-slot="select-trigger"],[data-review-popup]',
    ),
  ].slice(0, 80);
  return nodes.map((node) => {
    const rect = node.getBoundingClientRect();
    const name = (node.getAttribute("aria-label") ?? node.innerText ?? "").replace(/\s+/g, " ");
    return {
      element: `${node.tagName.toLowerCase()} "${name.trim().slice(0, 40)}"`,
      x: rect.left,
      y: rect.top,
      width: rect.width,
    };
  });
}

async function expanded(trigger) {
  return (await trigger.count()) && (await trigger.getAttribute("aria-expanded")) === "true";
}

export async function popupStability(page, settleAnimations) {
  const findings = [];
  const triggers = await page.evaluate(markTriggers, maxTriggers);
  for (const [index, description] of triggers.entries()) {
    const trigger = page.locator(`[data-review-popup="${index}"]`);
    if (!(await trigger.count())) continue;
    await trigger.scrollIntoViewIfNeeded();
    await settleAnimations(page);
    const before = await page.evaluate(measure);
    try {
      await trigger.click({ timeout: 5_000 });
    } catch {
      findings.push({
        check: "popup-stability",
        message: "Popup trigger could not be opened",
        elements: [description],
      });
      continue;
    }
    await settleAnimations(page);
    if (!description.includes("[aria-haspopup=") && !(await page.evaluate(revealsChoices))) {
      // A disclosure, not a popup: close it again and move on.
      if (await expanded(trigger)) await trigger.click({ timeout: 5_000 }).catch(() => {});
      await settleAnimations(page);
      continue;
    }
    const during = await page.evaluate(measure);
    const moved = before
      .map((box, at) => ({ box, open: during[at] }))
      .filter(
        ({ box, open }) =>
          open &&
          open.element === box.element &&
          (Math.abs(open.x - box.x) > tolerancePx ||
            Math.abs(open.y - box.y) > tolerancePx ||
            Math.abs(open.width - box.width) > tolerancePx),
      );
    if (moved.length) {
      const [{ box, open }] = moved;
      findings.push({
        check: "popup-stability",
        message: `Opening this popup moves page content (${moved.length} boxes; first by ${Math.round(open.x - box.x)}px x, ${Math.round(open.y - box.y)}px y, ${Math.round(open.width - box.width)}px width)`,
        elements: [description, ...moved.slice(0, 2).map((item) => item.box.element)],
      });
    }
    await page.keyboard.press("Escape");
    await settleAnimations(page);
    if (await expanded(trigger)) {
      findings.push({
        check: "popup-stability",
        message: "Escape does not close this popup",
        elements: [description],
      });
      await trigger.click({ timeout: 5_000 }).catch(() => {});
      await settleAnimations(page);
    }
  }
  await page.evaluate(() => {
    for (const node of document.querySelectorAll("[data-review-popup]"))
      node.removeAttribute("data-review-popup");
  });
  return { triggers: triggers.length, findings };
}
