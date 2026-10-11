// In-page probes for `lab console review`. Playwright serializes installProbes
// into each loaded document through the DevTools protocol (not a script tag), so
// the console's Content-Security-Policy stays unchanged. Probes only observe the
// DOM; every interaction is real browser input driven from review.mjs.

export function installProbes(rules) {
  if (window.__review) return;
  const interactiveSelector = [
    "a[href]",
    "button",
    "input:not([type=hidden])",
    "select",
    "textarea",
    "summary",
    '[role="button"]',
    '[role="link"]',
    '[role="tab"]',
    '[role="checkbox"]',
    '[role="radio"]',
    '[role="switch"]',
    '[role="combobox"]',
    '[role="menuitem"]',
    '[role="option"]',
    '[tabindex]:not([tabindex="-1"])',
  ].join(",");
  const controlSelector =
    'input:not([type=hidden]),select,textarea,button,a[href],[role="button"],[role="combobox"]';
  const tabbableSelector = [
    "a[href]",
    "button",
    "input:not([type=hidden])",
    "select",
    "textarea",
    "summary",
    "iframe",
    "[contenteditable=true]",
    "[tabindex]",
  ].join(",");
  const transparent = (value) => value === "transparent" || /rgba\(.*,\s*0\)$/.test(value);
  const normalize = (value) => value.replace(/\s+/g, " ").trim();
  let nextKey = 0;
  const key = (node) => {
    if (!node.dataset.reviewKey) node.dataset.reviewKey = `k${(nextKey += 1)}`;
    return node.dataset.reviewKey;
  };
  const describe = (node) => {
    if (!node || node.nodeType !== 1) return "document";
    const role = node.getAttribute("role");
    const name =
      node.getAttribute("aria-label") ||
      normalize(node.innerText ?? node.textContent ?? "").slice(0, 60) ||
      node.getAttribute("placeholder") ||
      node.getAttribute("title") ||
      "";
    const path = [];
    for (let cursor = node; cursor && cursor.nodeType === 1 && path.length < 4;) {
      const parent = cursor.parentElement;
      let part = cursor.tagName.toLowerCase();
      if (cursor.id && !/[:]/.test(cursor.id)) {
        path.unshift(`${part}#${cursor.id}`);
        break;
      }
      const slot = cursor.dataset?.slot;
      if (slot) part += `[data-slot=${slot}]`;
      else if (parent) {
        const same = [...parent.children].filter((child) => child.tagName === cursor.tagName);
        if (same.length > 1) part += `:nth-of-type(${same.indexOf(cursor) + 1})`;
      }
      path.unshift(part);
      cursor = parent;
    }
    return `${path.join(" > ")}${role ? ` [role=${role}]` : ""}${name ? ` "${name}"` : ""}`;
  };
  const opacityHidden = (node) => {
    for (let cursor = node; cursor && cursor.nodeType === 1; cursor = cursor.parentElement) {
      if (Number(getComputedStyle(cursor).opacity) === 0) return true;
    }
    return false;
  };
  // checkVisibility also excludes closed <details> content (content-visibility: hidden).
  const rendered = (node) => {
    if (!node || !node.isConnected || node.getClientRects().length === 0) return false;
    if (node.closest("[inert],[data-base-ui-inert]")) return false;
    if (!node.checkVisibility({ contentVisibilityAuto: true, visibilityProperty: true }))
      return false;
    return !opacityHidden(node);
  };
  const srOnly = (node) => {
    for (let cursor = node; cursor && cursor.nodeType === 1; cursor = cursor.parentElement) {
      const style = getComputedStyle(cursor);
      if (style.clip === "rect(0px, 0px, 0px, 0px)" || style.clipPath === "inset(50%)") return true;
      const rect = cursor.getBoundingClientRect();
      if (style.position === "absolute" && rect.width <= 1 && rect.height <= 1) return true;
    }
    return false;
  };
  // Intersect with every clipping ancestor; scrolled-away table cells are not visible.
  const clipped = (rect, node) => {
    let { left, top, right, bottom } = rect;
    for (let cursor = node; cursor && cursor !== document.body; cursor = cursor.parentElement) {
      const style = getComputedStyle(cursor);
      if (style.overflowX !== "visible" || style.overflowY !== "visible") {
        const box = cursor.getBoundingClientRect();
        if (style.overflowX !== "visible") {
          left = Math.max(left, box.left);
          right = Math.min(right, box.right);
        }
        if (style.overflowY !== "visible") {
          top = Math.max(top, box.top);
          bottom = Math.min(bottom, box.bottom);
        }
      }
      if (style.position === "fixed") break;
    }
    return right - left > 1 && bottom - top > 1 ? { left, top, right, bottom } : null;
  };
  // The nearest fixed or sticky layer. Content scrolled beneath a pinned header is
  // occluded by design, not overlapping; at scroll 0 every pair is still judged.
  const pinned = (node) => {
    for (let cursor = node; cursor && cursor.nodeType === 1; cursor = cursor.parentElement) {
      const position = getComputedStyle(cursor).position;
      if (position === "fixed" || position === "sticky") return cursor;
    }
    return null;
  };
  const scrolled = () =>
    scrollY > 0 ||
    [...document.querySelectorAll("*")].some(
      (node) => node.scrollTop > 0 && getComputedStyle(node).overflowY !== "visible",
    );
  const occluded = (a, b, moved) => moved && pinned(a) !== pinned(b);
  const intersection = (a, b) => ({
    width: Math.min(a.right, b.right) - Math.max(a.left, b.left),
    height: Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top),
  });
  const styleSnapshot = (node) => {
    if (!node || node.nodeType !== 1) return "";
    const style = getComputedStyle(node);
    const outline =
      style.outlineStyle === "none" || parseFloat(style.outlineWidth) === 0
        ? "none"
        : `${style.outlineStyle} ${style.outlineWidth} ${style.outlineColor} ${style.outlineOffset}`;
    const rect = node.getBoundingClientRect();
    return [
      outline,
      style.boxShadow,
      style.borderTopColor,
      style.borderBottomColor,
      style.borderLeftColor,
      style.borderRightColor,
      style.backgroundColor,
      style.color,
      style.textDecorationLine,
      style.clip,
      Math.round(rect.width),
      Math.round(rect.height),
    ].join("|");
  };
  const related = (node) => [
    node,
    node.parentElement,
    node.previousElementSibling,
    node.nextElementSibling,
  ];
  const unfocused = new Map();
  const isTabbable = (node) => {
    if (!node.matches(tabbableSelector) || node.tabIndex < 0) return false;
    if (node.disabled || node.closest("fieldset:disabled") || node.closest("[inert]")) return false;
    if (node.matches("[data-base-ui-focus-guard]")) return false;
    if (node.tagName === "SUMMARY" && node.parentElement?.tagName !== "DETAILS") return false;
    if (!node.isConnected || node.getClientRects().length === 0) return false;
    return node.checkVisibility({ contentVisibilityAuto: true, visibilityProperty: true });
  };
  const textRuns = (root) => {
    const runs = [];
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    const range = document.createRange();
    for (let text = walker.nextNode(); text; text = walker.nextNode()) {
      if (!text.nodeValue.trim()) continue;
      const parent = text.parentElement;
      if (!parent || parent.closest("script,style,noscript,template")) continue;
      if (!rendered(parent) || srOnly(parent)) continue;
      range.selectNodeContents(text);
      for (const rect of range.getClientRects()) {
        const box = clipped(rect, parent);
        if (box) runs.push({ text, parent, box });
      }
    }
    return runs;
  };
  const excluded = (node) => rules.excludedRegions.some((selector) => node.closest(selector));
  const compiled = [
    ...rules.bannedTerms.map((item) => ({
      rule: `banned term "${item.term}"`,
      regex: new RegExp(item.pattern, item.flags ?? "i"),
    })),
    ...rules.patterns.map((item) => ({
      rule: item.name,
      regex: new RegExp(item.pattern, item.flags ?? "i"),
    })),
  ];

  window.__review = {
    describe,
    layout(desktop) {
      const findings = [];
      const scroller = document.scrollingElement;
      const width = scroller.clientWidth;
      if (scroller.scrollWidth > width + 1) {
        const offenders = [...document.body.querySelectorAll("*")].filter((node) => {
          if (!rendered(node)) return false;
          const rect = node.getBoundingClientRect();
          if (rect.right + scrollX <= width + 1) return false;
          return ![...node.children].some(
            (child) => rendered(child) && child.getBoundingClientRect().right + scrollX > width + 1,
          );
        });
        findings.push({
          check: "horizontal-overflow",
          message: `Document is ${scroller.scrollWidth}px wide in a ${width}px viewport`,
          elements: offenders.slice(0, 5).map(describe),
        });
      }
      const moved = scrolled();
      const interactive = [...document.querySelectorAll(interactiveSelector)]
        .filter((node) => rendered(node) && !srOnly(node))
        .map((node) => ({ node, box: clipped(node.getBoundingClientRect(), node) }))
        .filter((item) => item.box);
      for (let i = 0; i < interactive.length; i += 1) {
        for (let j = i + 1; j < interactive.length; j += 1) {
          const a = interactive[i];
          const b = interactive[j];
          if (a.node.contains(b.node) || b.node.contains(a.node)) continue;
          if (occluded(a.node, b.node, moved)) continue;
          const overlap = intersection(a.box, b.box);
          if (overlap.width > 2 && overlap.height > 2) {
            findings.push({
              check: "interactive-overlap",
              message: `Interactive elements overlap by ${Math.round(overlap.width)}x${Math.round(overlap.height)}px`,
              elements: [describe(a.node), describe(b.node)],
            });
          }
        }
      }
      const runs = textRuns(document.body).sort((a, b) => a.box.top - b.box.top);
      for (let i = 0; i < runs.length; i += 1) {
        for (let j = i + 1; j < runs.length && runs[j].box.top < runs[i].box.bottom; j += 1) {
          const a = runs[i];
          const b = runs[j];
          if (a.text === b.text || occluded(a.parent, b.parent, moved)) continue;
          const overlap = intersection(a.box, b.box);
          const lineHeight = Math.min(a.box.bottom - a.box.top, b.box.bottom - b.box.top);
          if (overlap.width > 2 && overlap.height > lineHeight * 0.4) {
            findings.push({
              check: "text-overlap",
              message: `Text overlaps by ${Math.round(overlap.width)}x${Math.round(overlap.height)}px`,
              elements: [describe(a.parent), describe(b.parent)],
            });
          }
        }
      }
      // Text drawn over a textless control (input, icon button) hides one of them.
      for (const control of interactive) {
        if (!control.node.matches(controlSelector) || normalize(control.node.innerText ?? ""))
          continue;
        for (const run of runs) {
          if (control.node.contains(run.parent) || run.parent.contains(control.node)) continue;
          if (occluded(control.node, run.parent, moved)) continue;
          const labelled = run.parent.closest("label");
          if (labelled && (labelled.control === control.node || labelled.contains(control.node)))
            continue;
          const overlap = intersection(control.box, run.box);
          if (overlap.width > 2 && overlap.height > (run.box.bottom - run.box.top) * 0.4) {
            findings.push({
              check: "text-over-control",
              message: "Text overlaps a control",
              elements: [describe(run.parent), describe(control.node)],
            });
          }
        }
      }
      if (desktop) {
        const gap = document.querySelector('[data-slot="sidebar-gap"]');
        if (gap && rendered(gap.parentElement)) {
          const rect = gap.getBoundingClientRect();
          const bottom = rect.bottom + scrollY;
          const background = getComputedStyle(gap).backgroundColor;
          if (
            bottom < scroller.scrollHeight - 1 ||
            rect.top + scrollY > 1 ||
            transparent(background)
          ) {
            findings.push({
              check: "sidebar-height",
              message: `Sidebar column covers ${Math.round(rect.top + scrollY)}..${Math.round(bottom)}px of a ${scroller.scrollHeight}px document (background ${background})`,
              elements: [describe(gap)],
            });
          }
        }
      }
      // Deduplicate repeated pairs (a long table can repeat the same defect).
      const seen = new Set();
      return findings.filter((item) => {
        const id = `${item.check}:${item.elements.join("|")}`;
        if (seen.has(id)) return false;
        seen.add(id);
        return true;
      });
    },
    copy() {
      const findings = [];
      const seen = new Set();
      const inspect = (value, node, source) => {
        for (const { rule, regex } of compiled) {
          const match = regex.exec(value);
          if (!match) continue;
          const start = Math.max(0, match.index - 40);
          const excerpt = normalize(value.slice(start, match.index + match[0].length + 40));
          const id = `${rule}:${excerpt}`;
          if (seen.has(id)) continue;
          seen.add(id);
          findings.push({ check: "copy", rule, source, excerpt, elements: [describe(node)] });
        }
      };
      const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
      for (let text = walker.nextNode(); text; text = walker.nextNode()) {
        const parent = text.parentElement;
        // Field values (a textarea's text) are operator input, not console copy.
        if (!parent || !text.nodeValue.trim() || parent.closest("script,style,template,textarea"))
          continue;
        if (!rendered(parent) || srOnly(parent) || excluded(parent)) continue;
        inspect(text.nodeValue, parent, "text");
      }
      for (const node of document.querySelectorAll("[placeholder],[aria-label],[title]")) {
        if (!rendered(node) || excluded(node)) continue;
        for (const attribute of ["placeholder", "aria-label", "title"]) {
          const value = node.getAttribute(attribute);
          if (value) inspect(value, node, attribute);
        }
      }
      return findings;
    },
    // Secret values are compared in the page and never returned.
    leaks(secrets) {
      const values = [document.body.innerText];
      for (const node of document.querySelectorAll("input,textarea")) values.push(node.value);
      for (const node of document.querySelectorAll("[title],[aria-label]"))
        values.push(node.getAttribute("title") ?? "", node.getAttribute("aria-label") ?? "");
      return secrets.filter((secret) => values.some((value) => value.includes(secret))).length;
    },
    tabbables(root) {
      const scope = root ? document.querySelector(root) : document;
      unfocused.clear();
      const result = [];
      for (const node of scope.querySelectorAll(tabbableSelector)) {
        if (!isTabbable(node)) continue;
        const id = key(node);
        unfocused.set(id, related(node).map(styleSnapshot));
        result.push({
          key: id,
          description: describe(node),
          radioGroup: node.type === "radio" && node.name ? node.name : "",
        });
      }
      return result;
    },
    focusStart() {
      // Reset the sequential-navigation starting point to the document start.
      const anchor = document.createElement("span");
      anchor.tabIndex = -1;
      anchor.dataset.reviewAnchor = "true";
      document.body.prepend(anchor);
      anchor.focus({ preventScroll: true });
      window.scrollTo(0, 0);
    },
    focused(dialogSelector) {
      document.querySelector("[data-review-anchor]")?.remove();
      const node = document.activeElement;
      if (!node || node === document.body || node === document.documentElement)
        return { body: true };
      const id = node.dataset?.reviewKey ?? "";
      const before = unfocused.get(id);
      const after = related(node).map(styleSnapshot);
      const style = getComputedStyle(node);
      const indicator = before
        ? after.some((value, index) => value !== before[index])
        : (style.outlineStyle !== "none" && parseFloat(style.outlineWidth) > 0) ||
          style.boxShadow !== "none";
      const rect = node.getBoundingClientRect();
      let obscured = "";
      if (rect.width > 1 && rect.height > 1 && !srOnly(node)) {
        const x = Math.min(Math.max(rect.left + rect.width / 2, 0), innerWidth - 1);
        const y = Math.min(Math.max(rect.top + rect.height / 2, 0), innerHeight - 1);
        const top = document.elementFromPoint(x, y);
        if (top && top !== node && !node.contains(top) && !top.contains(node)) {
          const label = top.closest("label");
          if (!label || label.control !== node) obscured = describe(top);
        }
      }
      return {
        key: id,
        description: describe(node),
        indicator,
        obscured,
        inDialog: dialogSelector ? !!node.closest(dialogSelector) : false,
        visible: rect.width > 1 && rect.height > 1,
      };
    },
    focusKey(id) {
      const node = document.querySelector(`[data-review-key="${id}"]`);
      node?.focus();
      // Leaving a focused toast makes Sonner restore the previous focus; focus again.
      if (document.activeElement !== node) node?.focus();
      return document.activeElement === node;
    },
    activeKey() {
      const node = document.activeElement;
      return node && node !== document.body ? key(node) : "";
    },
    dialogTriggers() {
      const selector = [
        '[aria-haspopup="dialog"]:not([role="menuitem"])',
        '[data-slot$="dialog-trigger"]',
        '[data-slot="sheet-trigger"]',
        // Below the md breakpoint the sidebar trigger opens the navigation sheet.
        ...(matchMedia("(max-width: 767px)").matches ? ['[data-slot="sidebar-trigger"]'] : []),
      ].join(",");
      return [...document.querySelectorAll(selector)]
        .filter((node) => isTabbable(node) && !node.closest('[role="dialog"]'))
        .map((node) => ({ key: key(node), description: describe(node) }));
    },
    menuTriggers() {
      return [...document.querySelectorAll('[aria-haspopup="menu"]')]
        .filter((node) => isTabbable(node) && !node.closest('[role="dialog"]'))
        .map((node) => ({ key: key(node), description: describe(node) }));
    },
    openMenuDialogItems() {
      const menu = [...document.querySelectorAll('[role="menu"]')].find(rendered);
      if (!menu) return null;
      return [...menu.querySelectorAll('[role="menuitem"]')]
        .filter((node) => rendered(node) && node.getAttribute("aria-haspopup") === "dialog")
        .filter((node) => node.getAttribute("aria-disabled") !== "true")
        .map((node) => normalize(node.innerText));
    },
    highlightedMenuItem() {
      const node = document.activeElement;
      return node?.getAttribute("role") === "menuitem" ? normalize(node.innerText) : "";
    },
    openDialog() {
      const dialogs = [...document.querySelectorAll('[role="dialog"],[role="alertdialog"]')].filter(
        (node) => rendered(node) && !node.closest("[data-sonner-toaster]"),
      );
      const node = dialogs.at(-1);
      if (!node) return null;
      node.dataset.reviewDialog = "open";
      return {
        description: describe(node),
        // Base UI modal dialogs omit aria-modal but mark the rest of the page inert.
        modal:
          node.getAttribute("aria-modal") === "true" ||
          node.getAttribute("role") === "alertdialog" ||
          document.querySelector("[data-base-ui-inert]") !== null,
        named: !!(
          node.getAttribute("aria-label") ||
          (node.getAttribute("aria-labelledby") &&
            document.getElementById(node.getAttribute("aria-labelledby"))?.textContent.trim())
        ),
        focusInside: node.contains(document.activeElement),
        tabbables: [...node.querySelectorAll(tabbableSelector)].filter(isTabbable).length,
      };
    },
    dialogOpen() {
      const node = document.querySelector('[data-review-dialog="open"]');
      return !!node && rendered(node);
    },
    clearDialogMark() {
      for (const node of document.querySelectorAll("[data-review-dialog]"))
        delete node.dataset.reviewDialog;
    },
    settled() {
      const busy = [...document.querySelectorAll('[data-slot="skeleton"],[role="status"]')].some(
        (node) =>
          rendered(node) &&
          (node.dataset.slot === "skeleton" || /^Loading\b/.test(normalize(node.innerText))),
      );
      return !busy && document.readyState === "complete";
    },
    page() {
      return {
        path: location.pathname,
        heading: normalize(document.querySelector("h1")?.innerText ?? ""),
        routeError:
          normalize(document.querySelector("h1")?.innerText ?? "") === "Unable to load the console",
        main: !!document.getElementById("main"),
        tabs: [
          ...(document
            .querySelector('#main [role="tablist"], main [role="tablist"]')
            ?.querySelectorAll('[role="tab"]') ?? []),
        ]
          .filter(rendered)
          .map((node) => normalize(node.innerText)),
      };
    },
    // A named button must be visible; when disabled it must reference a visible reason.
    expectButton(name) {
      const button = [...document.querySelectorAll('button,[role="button"]')].find(
        (node) => rendered(node) && normalize(node.innerText) === name,
      );
      if (!button) return `Button "${name}" is missing`;
      if (!button.disabled && button.getAttribute("aria-disabled") !== "true") return "";
      const reason = (button.getAttribute("aria-describedby") ?? "")
        .split(/\s+/)
        .map((id) => document.getElementById(id))
        .find((node) => node && rendered(node) && normalize(node.innerText));
      return reason ? "" : `Disabled button "${name}" does not describe why`;
    },
    toast() {
      const toast = [...document.querySelectorAll("[data-sonner-toast]")].find(rendered);
      if (!toast) return null;
      const style = getComputedStyle(toast);
      const toaster = toast.closest("[data-sonner-toaster]");
      const rect = toast.getBoundingClientRect();
      const problems = [];
      if (!toaster || getComputedStyle(toaster).position !== "fixed")
        problems.push("toaster is not fixed-position");
      if (transparent(style.backgroundColor)) problems.push("toast has no background");
      if (style.boxShadow === "none" && parseFloat(style.borderTopWidth) === 0)
        problems.push("toast has no border or shadow");
      if (rect.left < 0 || rect.right > innerWidth || rect.top < 0 || rect.bottom > innerHeight)
        problems.push("toast is outside the viewport");
      if (style.listStyleType !== "none" && toast.tagName === "LI")
        problems.push("toast renders as a list item");
      return { text: normalize(toast.innerText).slice(0, 80), problems };
    },
  };
}
