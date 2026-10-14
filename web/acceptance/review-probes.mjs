// SPDX-License-Identifier: Apache-2.0

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
  const identifierRules = rules.identifiers.patterns.map((item) => ({
    rule: item.name,
    regex: new RegExp(item.pattern, "g"),
  }));
  const identifierAllow = new Set(rules.identifiers.allow);
  const identifierScope = rules.identifiers.singleTokenScope;
  const idInputPattern = new RegExp(rules.idInputPattern.pattern, rules.idInputPattern.flags);
  const byteValue = new RegExp(rules.rawByteValue.value, rules.rawByteValue.flags);
  const byteLabel = new RegExp(rules.rawByteValue.label, rules.rawByteValue.flags);
  const freeformExempt = new Set(rules.freeformInput.exemptTypes);
  const domainLabel = new RegExp(rules.freeformInput.domainLabel, "i");
  const searchLabel = new RegExp(rules.freeformInput.searchLabel, "i");
  // Same normalization as normalizeLabel in web/eslint/freeform-input.mjs.
  const normalizeLabel = (value) =>
    value
      .toLowerCase()
      .replace(/\([^)]*\)/g, " ")
      .replace(/[\u2026:*?!.,;"'`_/-]+/g, " ")
      .replace(/\s+/g, " ")
      .trim()
      .replace(/(?:^| )(?:optional|required)$/, "")
      .trim();
  // Accessible label sources of a form control, without the control's own value.
  const labelSources = (node) => [
    node.getAttribute("aria-label") ?? "",
    ...(node.getAttribute("aria-labelledby") ?? "")
      .split(/\s+/)
      .filter(Boolean)
      .map((id) => document.getElementById(id)?.textContent ?? ""),
    ...[...(node.labels ?? [])].map((label) => label.textContent ?? ""),
    node.getAttribute("placeholder") ?? "",
    node.getAttribute("name") ?? "",
  ];
  // A bare number names bytes through its nearest short labelled container
  // (a fact row or list item) or, inside a table, its column header.
  const bytesLabelled = (node) => {
    const cell = node.closest("td,th");
    if (cell) {
      const table = cell.closest("table");
      const header = table?.querySelectorAll("thead tr > *")[cell.cellIndex];
      if (header && byteLabel.test(header.textContent ?? "")) return true;
    }
    for (let scope = node.parentElement; scope && scope !== document.body;) {
      const text = normalize(scope.textContent ?? "");
      if (text.length > 160) return false;
      if (byteLabel.test(text)) return true;
      scope = scope.parentElement;
    }
    return false;
  };
  const visibleText = (node) => rendered(node) && !srOnly(node) && normalize(node.innerText ?? "");
  const enabledAction = (node) =>
    rendered(node) &&
    !srOnly(node) &&
    !node.disabled &&
    !node.closest("fieldset:disabled") &&
    node.getAttribute("aria-disabled") !== "true" &&
    !!normalize(node.innerText || node.getAttribute("aria-label") || "");
  const actionsIn = (root) =>
    [root, ...root.querySelectorAll("a[href],button,input,select,textarea,[role=button]")]
      .filter((node) => node.matches("a[href],button,input,select,textarea,[role=button]"))
      .filter(enabledAction);
  const statesIn = (root) =>
    [root, ...root.querySelectorAll("[data-review-state]")]
      .filter((node) => ["clear", "blocked"].includes(node.dataset.reviewState))
      .filter(visibleText);

  window.__review = {
    describe,
    pov(contract) {
      const findings = [];
      const add = (message, nodes = []) =>
        findings.push({ check: "pov-structure", message, elements: nodes.map(describe) });
      if (!contract) {
        add("Route has no explicit POV coverage contract");
        return { findings, mode: "uncontracted" };
      }
      const main = document.querySelector("main, [role=main], #main");
      if (!main) {
        add("Page has no main-content region for action coverage");
        return { findings, mode: contract.mode };
      }
      const page = contract.page
        ? [main, ...main.querySelectorAll("[data-review-page]")].find(
            (node) => node.dataset.reviewPage === contract.page && rendered(node),
          )
        : main;
      if (!page) {
        add(`Missing visible data-review-page="${contract.page}" region`);
        return { findings, mode: contract.mode };
      }
      const states = statesIn(page);
      const primary = [page, ...page.querySelectorAll("[data-review-next-action]")]
        .filter((node) => node.hasAttribute("data-review-next-action"))
        .flatMap(actionsIn);
      const controls = actionsIn(page);
      const candidates = contract.mode === "semantic" ? primary : controls;
      if (!candidates.length && !states.length)
        add(
          contract.mode === "semantic"
            ? "No marked enabled next action or explicit clear/blocked state"
            : "No enabled main-content control or explicit clear/blocked state (structural only)",
        );
      const metrics = [...page.querySelectorAll("[data-review-metric]")].filter(rendered);
      if (
        metrics.length < contract.minimumMetrics &&
        !states.some((node) => node.dataset.reviewState === "blocked")
      )
        add(`Expected at least ${contract.minimumMetrics} marked metric or explicit blocked state`);
      for (const metric of metrics)
        if (!actionsIn(metric).length && !statesIn(metric).length)
          add("Marked metric has no enabled action or explicit clear/blocked state", [metric]);
      return {
        findings,
        mode: contract.mode,
        primaryActions: primary.length,
        genericControls: controls.length,
        explicitStates: states.length,
        markedMetrics: metrics.length,
        limitation: "Presence only; human review must judge relevance, completeness and truth.",
      };
    },
    destructive() {
      const dialog = document.querySelector('[data-review-dialog="open"]');
      const findings = [];
      const observed = [];
      if (!dialog) return { findings, observed };
      const summaries = [dialog, ...dialog.querySelectorAll("[data-review-destructive]")].filter(
        (node) => node.hasAttribute("data-review-destructive") && rendered(node),
      );
      for (const summary of summaries) {
        const id = summary.dataset.reviewDestructive;
        if (id) observed.push(id);
        const confirm = [...summary.querySelectorAll("[data-review-confirm]")].find(rendered);
        if (!confirm)
          findings.push({
            check: "destructive-summary",
            message: "Marked destructive dialog has no visible confirmation marker",
            elements: [describe(summary)],
          });
        for (const field of ["targets", "count", "effects", "reversibility", "approval"]) {
          const nodes = [...summary.querySelectorAll(`[data-review-impact="${field}"]`)];
          if (
            !nodes.some(
              (node) =>
                visibleText(node) &&
                (!confirm ||
                  !!(node.compareDocumentPosition(confirm) & Node.DOCUMENT_POSITION_FOLLOWING)),
            )
          )
            findings.push({
              check: "destructive-summary",
              message: `Missing visible ${field} summary before destructive confirmation`,
              elements: [describe(summary)],
            });
        }
      }
      return { findings, observed };
    },
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
      // design.md Type: long hostnames and names wrap. A single-line ellipsis
      // hides the identifying end of the value (seen with the seeded 70-character
      // hostname). Multi-line clamps of descriptions are a summary pattern and
      // are not judged; the one-line header breadcrumb repeats the page heading,
      // which carries the full name.
      for (const node of document.body.querySelectorAll("*")) {
        if (!rendered(node) || srOnly(node) || !normalize(node.innerText ?? "")) continue;
        if (node.closest('[data-slot="breadcrumb"]')) continue;
        if (getComputedStyle(node).textOverflow !== "ellipsis") continue;
        if (node.scrollWidth > node.clientWidth + 1)
          findings.push({
            check: "text-truncated",
            message: "Text is cut off with an ellipsis; let long names wrap",
            elements: [describe(node)],
          });
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
        const railElement = document.querySelector("[data-shell-rail]");
        if (railElement && rendered(railElement)) {
          const logo = railElement.querySelector("[data-sidebar-logo]");
          if (!logo || !rendered(logo)) {
            findings.push({
              check: "sidebar-logo-centered",
              message: "Navigation rail has no visible logo",
              elements: [describe(railElement)],
            });
          } else {
            const rail = railElement.getBoundingClientRect();
            const mark = logo.getBoundingClientRect();
            const offset = Math.abs(mark.left + mark.width / 2 - (rail.left + rail.width / 2));
            if (offset > 1 || mark.left < rail.left || mark.right > rail.right) {
              findings.push({
                check: "sidebar-logo-centered",
                message: `Navigation rail logo is ${offset.toFixed(1)}px off center`,
                elements: [describe(logo)],
              });
            }
          }
        }
        const column = document.querySelector("[data-shell-rail-column]");
        if (column && rendered(column)) {
          const rect = column.getBoundingClientRect();
          const bottom = rect.bottom + scrollY;
          const background = getComputedStyle(column).backgroundColor;
          if (
            bottom < scroller.scrollHeight - 1 ||
            rect.top + scrollY > 1 ||
            transparent(background)
          ) {
            findings.push({
              check: "rail-height",
              message: `Navigation rail column covers ${Math.round(rect.top + scrollY)}..${Math.round(bottom)}px of a ${scroller.scrollHeight}px document (background ${background})`,
              elements: [describe(column)],
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
      const report = (rule, value, index, length, node, source) => {
        const start = Math.max(0, index - 40);
        const excerpt = normalize(value.slice(start, index + length + 40));
        const id = `${rule}:${excerpt}`;
        if (seen.has(id)) return;
        seen.add(id);
        findings.push({ check: "copy", rule, source, excerpt, elements: [describe(node)] });
      };
      const inspect = (value, node, source, identifiers, ste = true) => {
        const vocabulary = ste && rules.vocabulary;
        const exempt = (rule) => {
          const declaration = node.closest("[data-ste-exempt]")?.getAttribute("data-ste-exempt");
          return declaration?.split(";").some((entry) => {
            const [name, ...reason] = entry.split(":");
            return name.trim() === rule && reason.join(":").trim().length > 0;
          });
        };
        if (vocabulary) {
          const sentences = value.match(/[^.!?]+(?:[.!?]+|$)/g) ?? [];
          for (const sentence of sentences) {
            const words = sentence.match(/\b[\p{L}\p{N}]+(?:['’-][\p{L}\p{N}]+)*\b/gu) ?? [];
            const procedure =
              node.closest("[data-ste-procedure]") ||
              /^(?:select|enter|choose|review|confirm|remove|add|open|close|use|request|wait|check|save|create|start|stop|retry|refresh|copy|install|connect|disconnect|keep|enable|disable|set|publish|assign|end|read|send|allow|block|reject|approve|revoke|rotate|unlock|lock|wipe|restart|restore|configure|replace|reset|clear|cancel|discard|edit|type|run|follow|compare|inspect|provide|return|contact|ask|do not)\b/i.test(
                sentence.trim(),
              );
            const limit = procedure
              ? vocabulary.sentenceLimits.procedure
              : vocabulary.sentenceLimits.description;
            if (words.length > limit && !exempt("sentence-length"))
              report("STE sentence length", sentence, 0, sentence.length, node, source);
          }
          if (!exempt("passive-voice")) {
            const passive =
              /\b(?:am|is|are|was|were|be|been|being)\s+(?:\w+ly\s+)?(?:\w+ed|given|shown|sent|written|taken|known|done|made|built|found|held)\b/i.exec(
                value,
              );
            if (passive)
              report("STE passive voice", value, passive.index, passive[0].length, node, source);
          }
          if (!exempt("vocabulary")) {
            for (const term of vocabulary.approvedTerms) {
              for (const synonym of term.forbiddenSynonyms) {
                const escaped = synonym.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
                const match = new RegExp(
                  `(?<![\\p{L}\\p{N}-])${escaped}(?![\\p{L}\\p{N}-])`,
                  "iu",
                ).exec(value);
                if (match)
                  report(
                    `STE use "${term.term}"`,
                    value,
                    match.index,
                    match[0].length,
                    node,
                    source,
                  );
              }
            }
          }
          if (!exempt("noun-cluster")) {
            const nouns = new Set(vocabulary.nounWords);
            const tokens = [...value.matchAll(/\b[\p{L}]+\b/gu)];
            let run = [];
            for (const token of tokens) {
              const previous = run.at(-1);
              const contiguous =
                !previous ||
                /^\s+$/.test(value.slice(previous.index + previous[0].length, token.index));
              run =
                nouns.has(token[0].toLowerCase()) && contiguous
                  ? [...run, token]
                  : nouns.has(token[0].toLowerCase())
                    ? [token]
                    : [];
              if (run.length === 4)
                report(
                  "STE noun cluster",
                  value,
                  run[0].index,
                  token.index + token[0].length - run[0].index,
                  node,
                  source,
                );
            }
          }
        }
        // Existing identifier rules inspect individual non-technical text nodes.
        // Sentence aggregation must not reclassify a block's technical values.
        if (source === "primary text") return;
        for (const { rule, regex } of compiled) {
          const match = regex.exec(value);
          if (match) report(rule, value, match.index, match[0].length, node, source);
        }
        if (!identifiers) return;
        for (const { rule, regex } of identifierRules) {
          const match = [...value.matchAll(regex)].find((item) => !identifierAllow.has(item[0]));
          if (match) report(rule, value, match.index, match[0].length, node, source);
        }
      };
      const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
      const steBlocks = new Set();
      for (let text = walker.nextNode(); text; text = walker.nextNode()) {
        const parent = text.parentElement;
        // Field values (a textarea's text) are operator input, not console copy.
        if (!parent || !text.nodeValue.trim() || parent.closest("script,style,template,textarea"))
          continue;
        if (!rendered(parent) || srOnly(parent) || excluded(parent)) continue;
        const block =
          parent.closest(
            "p,label,button,a,summary,h1,h2,h3,h4,h5,h6,li,dt,dd,[role=alert],[role=status]",
          ) ?? parent;
        if (!steBlocks.has(block)) {
          steBlocks.add(block);
          const parts = [];
          const blockWalker = document.createTreeWalker(block, NodeFilter.SHOW_TEXT);
          for (let child = blockWalker.nextNode(); child; child = blockWalker.nextNode()) {
            const element = child.parentElement;
            if (
              element &&
              rendered(element) &&
              !srOnly(element) &&
              !excluded(element) &&
              !element.closest("script,style,template,textarea")
            )
              parts.push(child.nodeValue);
          }
          const primaryText = parts.join(" ");
          inspect(normalize(primaryText), block, "primary text", false);
        }
        const phrase = normalize(text.nodeValue).includes(" ");
        inspect(text.nodeValue, parent, "text", phrase || !!parent.closest(identifierScope), false);
        if (byteValue.test(text.nodeValue) && bytesLabelled(parent)) {
          const excerpt = normalize(parent.parentElement?.textContent ?? text.nodeValue).slice(
            0,
            120,
          );
          const id = `raw byte count:${excerpt}`;
          if (!seen.has(id)) {
            seen.add(id);
            findings.push({
              check: "copy",
              rule: "raw byte count",
              source: "text",
              excerpt,
              elements: [describe(parent)],
            });
          }
        }
      }
      for (const node of document.querySelectorAll("[placeholder],[aria-label],[title]")) {
        if (!rendered(node) || excluded(node)) continue;
        for (const attribute of ["placeholder", "aria-label", "title"]) {
          const value = node.getAttribute(attribute);
          if (value) inspect(value, node, attribute, true);
        }
      }
      for (const node of document.querySelectorAll("a[href]")) {
        let url;
        try {
          url = new URL(node.getAttribute("href"), location.href);
        } catch {
          report("invalid console link", node.getAttribute("href"), 0, 120, node, "href");
          continue;
        }
        if (url.origin === location.origin) continue;
        const advisory =
          node.getAttribute("data-console-link") === "vendor-advisory" &&
          url.protocol === "https:" &&
          !url.username &&
          !url.password &&
          (!url.port || url.port === "443") &&
          rules.vocabulary?.vendorAdvisoryHosts.includes(url.hostname);
        if (!advisory) report("external console link", url.href, 0, url.href.length, node, "href");
      }
      return findings;
    },
    idInputs() {
      const findings = [];
      const labels = [...document.querySelectorAll("label")];
      for (const node of document.querySelectorAll('input,textarea,select,[role="combobox"]')) {
        if (!rendered(node)) continue;
        if (
          node.closest('[data-slot="technical-details"]') &&
          (node.readOnly || node.getAttribute("aria-readonly") === "true")
        )
          continue;
        const sources = [
          node.getAttribute("aria-label") ?? "",
          ...(node.getAttribute("aria-labelledby") ?? "")
            .split(/\s+/)
            .filter(Boolean)
            .map((id) => document.getElementById(id)?.textContent ?? ""),
          ...labels
            .filter((label) => (node.id && label.htmlFor === node.id) || label.contains(node))
            .map((label) => label.textContent ?? ""),
          node.getAttribute("placeholder") ?? "",
        ];
        const prompt = sources.find((value) => {
          idInputPattern.lastIndex = 0;
          return idInputPattern.test(value);
        });
        if (prompt) {
          findings.push({
            check: "id-input",
            message: `Input asks for an ID: "${normalize(prompt)}". Use a searchable picker.`,
            elements: [describe(node)],
          });
        }
      }
      return findings;
    },
    // docs/engineering.md "Free-text inputs": a rendered text-like input either
    // declares why its value is genuinely new (data-freeform) or is a picker. A
    // label naming existing values fails even when declared. Picker and palette
    // search boxes (cmdk) and read-only display fields are not entry fields.
    freeform(root) {
      const scope = root ? document.querySelector(root) : document;
      const findings = [];
      if (!scope) return findings;
      for (const node of scope.querySelectorAll("input,textarea")) {
        if (!rendered(node) || node.readOnly || node.matches("[cmdk-input]")) continue;
        // Base UI selects keep an aria-hidden, untabbable native input for forms.
        if (node.closest('[aria-hidden="true"]') && node.tabIndex < 0) continue;
        if (node.tagName === "INPUT" && freeformExempt.has(node.type)) continue;
        const sources = labelSources(node).map(normalizeLabel).filter(Boolean);
        const label = normalize(sources[0] ?? "") || "unlabelled";
        const search =
          node.type === "search" ||
          node.getAttribute("role") === "searchbox" ||
          sources.some((value) => searchLabel.test(value));
        const domain = search ? undefined : sources.find((value) => domainLabel.test(value));
        if (domain)
          findings.push({
            check: "freeform-input",
            message: `Free-text input "${domain}" refers to values that already exist. Use a searchable picker or a select.`,
            elements: [describe(node)],
          });
        else if (!node.dataset.freeform?.trim())
          findings.push({
            check: "freeform-input",
            message: `Free-text input "${label}" has no data-freeform declaration`,
            elements: [describe(node)],
          });
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
        // Popovers (pickers) are non-modal: Tab leaves and closes them.
        modal:
          node.getAttribute("aria-modal") === "true" ||
          node.getAttribute("role") === "alertdialog" ||
          (node.dataset.slot !== "popover-content" &&
            document.querySelector("[data-base-ui-inert]") !== null),
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
    // A rendered form needs a submit control: shadcn/Base UI buttons default to
    // type="button", so a form without an explicit submit button never submits.
    forms() {
      return [...document.querySelectorAll("form")]
        .filter(
          (form) =>
            rendered(form) &&
            !form.querySelector('button[type="submit"],input[type="submit"],input[type="image"]'),
        )
        .map((form) => ({
          check: "form-submit",
          message: "Form has no submit button",
          elements: [describe(form)],
        }));
    },
    // Console-wide conventions (docs/design.md, docs/engineering.md frontend):
    // one Details disclosure per card, one Refresh per page, no paging controls
    // for a list that fits on one page, and no silently clipped tables.
    conventions(listPage = false) {
      const findings = [];
      const outsideDialog = (node) => !node.closest('[role="dialog"],[role="alertdialog"]');
      const cards = new Map();
      for (const details of document.querySelectorAll("details")) {
        const summary = details.querySelector(":scope > summary");
        if (!summary || !rendered(summary)) continue;
        const card = details.parentElement?.closest(
          '[data-slot="card"],article,li,tr,[role="dialog"],[role="alertdialog"]',
        );
        if (!card) continue;
        cards.set(card, [...(cards.get(card) ?? []), summary]);
      }
      for (const [card, summaries] of cards) {
        if (summaries.length < 2) continue;
        findings.push({
          check: "details-per-card",
          message: `${summaries.length} disclosures in one card (${summaries.map((node) => `"${normalize(node.innerText)}"`).join(", ")}); keep at most one, for secondary data only`,
          elements: [describe(card)],
        });
      }
      const refreshes = [...document.querySelectorAll('button,[role="button"],a[href]')].filter(
        (node) =>
          rendered(node) &&
          !srOnly(node) &&
          outsideDialog(node) &&
          /^refresh\b/i.test(normalize(node.innerText ?? "")),
      );
      if (refreshes.length > 1) {
        findings.push({
          check: "single-refresh",
          message: `${refreshes.length} Refresh buttons on one page; keep one in the page header`,
          elements: refreshes.map(describe),
        });
      }
      const buttonNamed = (name) =>
        [...document.querySelectorAll("button")].filter(
          (node) => rendered(node) && outsideDialog(node) && normalize(node.innerText) === name,
        );
      for (const first of buttonNamed("First page")) {
        const scope = first.parentElement;
        const next = [...(scope?.querySelectorAll("button") ?? [])].find(
          (node) => normalize(node.innerText) === "Next page",
        );
        if (first.disabled && next?.disabled) {
          findings.push({
            check: "single-page-pagination",
            message:
              "Disabled First page and Next page on a list that fits on one page; use ListPagination",
            elements: [describe(scope)],
          });
        }
      }
      for (const node of document.querySelectorAll("label")) {
        if (rendered(node) && outsideDialog(node) && normalize(node.innerText) === "Page size") {
          findings.push({
            check: "single-page-pagination",
            message: 'Standalone "Page size" control; use ListPagination\'s Rows per page',
            elements: [describe(node)],
          });
        }
      }
      for (const table of document.querySelectorAll("table")) {
        if (!rendered(table)) continue;
        let scroller = table.parentElement;
        while (scroller && scroller !== document.body) {
          const overflowX = getComputedStyle(scroller).overflowX;
          if (overflowX === "auto" || overflowX === "scroll" || overflowX === "hidden") break;
          scroller = scroller.parentElement;
        }
        if (!scroller || scroller === document.body) continue;
        if (scroller.scrollWidth <= scroller.clientWidth + 1) continue;
        const hint = scroller.parentElement?.querySelector(
          ':scope > [data-slot="table-scroll-hint"]',
        );
        if (!hint || !rendered(hint)) {
          findings.push({
            check: "table-overflow-hint",
            message: `Table is ${scroller.scrollWidth}px wide in a ${scroller.clientWidth}px column with no scroll hint`,
            elements: [describe(table)],
          });
        }
      }
      // On a phone, a list page (review.mjs listRoutes) shows its first row on the
      // first screen: filters fold into FilterPanel and decision forms open on demand.
      if (listPage && innerWidth < 768) {
        const main = document.querySelector("main") ?? document.body;
        const table = [...main.querySelectorAll("table")].find(rendered);
        const row = table && [...table.querySelectorAll("tbody tr")].find(rendered);
        if (row) {
          const top = row.getBoundingClientRect().top + scrollY;
          if (top >= innerHeight) {
            findings.push({
              check: "mobile-first-screen",
              message: `First list row starts at ${Math.round(top)}px, below the ${innerHeight}px first screen; fold filters into FilterPanel`,
              elements: [describe(row)],
            });
          }
        }
      }
      return findings;
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
