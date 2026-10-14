// SPDX-License-Identifier: Apache-2.0
// Project additions: Apache-2.0; shadcn-derived portions: MIT.
// Copyright (c) 2023 shadcn; see web/LICENSE.shadcn for the retained MIT notice.

import { useLayoutEffect, type ComponentProps } from "react";

// Modal page scroll lock for Dialog and Sheet backdrops. Base UI's own lock only
// hides overflow on the scrolled document, so the document stays scrolled and
// everything that renders the whole document (a full-page capture, print)
// draws the fixed backdrop, sidebar and header at the scroll offset: the top of
// the page stays unblurred and the dialog sits over the content below it.
// While a modal is open this lock moves the page's scroll offset onto the app
// root (#root in web/index.html): nothing moves on screen, the sticky header
// sticks to the root, and the document is exactly one viewport tall, so every
// fixed layer covers all of it. Base UI's lock finds the page already locked
// (overflow hidden on <html>) and leaves it alone until this lock is released.
let holders = 0;
let release: (() => void) | undefined;

function lockPage(): () => void {
  const root = document.getElementById("root");
  if (!root) return () => {};
  const html = document.documentElement;
  // Classic scrollbars take width; keep their gutter so the layout doesn't widen.
  const insetScrollbar = window.innerWidth > html.clientWidth;
  const { scrollX: left, scrollY: top } = window;
  const saved = {
    htmlOverflow: html.style.overflow,
    htmlGutter: html.style.scrollbarGutter,
    rootHeight: root.style.height,
    rootOverflow: root.style.overflow,
  };
  // CSSOM assignments only: the console's CSP blocks style attributes.
  html.style.overflow = "hidden";
  if (insetScrollbar) html.style.scrollbarGutter = "stable";
  root.style.height = "100dvh";
  root.style.overflow = "hidden";
  // Transfer the offset: retaining it on both the viewport and root doubles the scroll.
  window.scrollTo({ left: 0, top: 0, behavior: "instant" });
  root.scrollTo({ left, top, behavior: "instant" });
  return () => {
    // Focus moves while locked scroll the root; the page keeps that position.
    const { scrollLeft, scrollTop } = root;
    html.style.overflow = saved.htmlOverflow;
    html.style.scrollbarGutter = saved.htmlGutter;
    root.style.height = saved.rootHeight;
    root.style.overflow = saved.rootOverflow;
    window.scrollTo({ left: scrollLeft, top: scrollTop, behavior: "instant" });
  };
}

// A backdrop element that holds the page lock while its popup is open. Nested
// modals share one lock; the last one to close releases it.
export function ScrollLockingBackdrop({
  locked,
  ...props
}: ComponentProps<"div"> & { locked: boolean }) {
  useLayoutEffect(() => {
    if (!locked) return;
    holders += 1;
    if (holders === 1) release = lockPage();
    return () => {
      holders -= 1;
      if (holders > 0) return;
      release?.();
      release = undefined;
    };
  }, [locked]);
  return <div {...props} />;
}
