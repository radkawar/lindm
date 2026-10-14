// SPDX-License-Identifier: Apache-2.0
// Project additions: Apache-2.0; shadcn-derived portions: MIT.
// Copyright (c) 2023 shadcn; see web/LICENSE.shadcn for the retained MIT notice.

// Built from the existing shadcn/ui menu, sheet and tooltip primitives (MIT; web/LICENSE.shadcn).
import { Link, useRouterState } from "@tanstack/react-router";
import { Menu } from "@base-ui/react/menu";
import {
  ArrowUpRightIcon,
  ChevronDownIcon,
  LogOutIcon,
  MenuIcon,
  PanelLeftCloseIcon,
  PanelLeftOpenIcon,
  SettingsIcon,
} from "lucide-react";
import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import type { SessionPrincipal } from "../../../gen/lindm/auth/v1/auth_pb";
import { ThemeToggle } from "./theme-toggle";
import { BreadcrumbTitleContext } from "./breadcrumb-title";
import {
  navigation,
  navigationAreas,
  relatedNavigation,
  visibleNavigation,
  type NavigationArea,
} from "./navigation";
import { BrandLogo } from "@/components/ui/brand-logo";
import { roleLabel } from "@/lib/roles";
import { Badge } from "@/components/ui/badge";
import { StatusBadge } from "@/components/ui/status-badge";
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbLink,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb";
import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";

const pageLinkClass =
  "flex min-h-10 items-center gap-2 px-3 py-2 text-sm outline-none hover:bg-sidebar-accent focus-visible:ring-2 focus-visible:ring-ring aria-[current=page]:bg-sidebar-accent aria-[current=page]:font-medium aria-[current=page]:text-primary";

function savedPagesOpen(key: string) {
  try {
    return localStorage.getItem(key) !== "collapsed";
  } catch {
    // Navigation stays usable when browser storage is disabled.
    return true;
  }
}

export function ConsoleShell({
  userLabel,
  role,
  principal,
  loggingOut,
  onLogout,
  children,
  commandPalette,
}: {
  userLabel: string;
  role: string;
  principal: SessionPrincipal;
  loggingOut: boolean;
  onLogout: () => void;
  children: ReactNode;
  commandPalette: ReactNode;
}) {
  const pathname = useRouterState({ select: (state) => state.location.pathname });
  const [recordTitle, setRecordTitle] = useState<string | null>(null);
  const [mobileOpen, setMobileOpen] = useState(false);
  // Only the public account identity and a display preference enter storage, never session tokens.
  const preferenceKey = `lindm-page-navigation:${JSON.stringify([principal.issuer, principal.subject])}`;
  const [pagesOpen, setPagesOpen] = useState(() => savedPagesOpen(preferenceKey));
  const [announcement, setAnnouncement] = useState("");
  const collapseButton = useRef<HTMLButtonElement>(null);
  const pagesColumn = useRef<HTMLElement>(null);
  const items = visibleNavigation(principal);
  const currentPage = navigation.find(
    (item) => pathname === item.to || pathname.startsWith(`${item.to}/`),
  );
  const areas = navigationAreas.filter((area) => items.some((item) => item.group === area.label));
  const area: NavigationArea = currentPage?.group ?? areas[0]?.label ?? "Fleet";
  const canOpenPage = currentPage !== undefined && items.some((item) => item.to === currentPage.to);
  const pages = items.filter((item) => item.group === area);
  const related = items.filter((item) => relatedNavigation[area].includes(item.to));
  const title = currentPage?.label ?? "Console";
  const isDetail = currentPage && pathname !== currentPage.to;
  const deviceId = currentPage?.to === "/devices" ? pathname.split("/")[2] : undefined;
  const subPage =
    currentPage?.to === "/devices"
      ? pathname.includes("/actions/new/")
        ? "New action"
        : pathname.includes("/actions/")
          ? "Action status"
          : pathname.includes("/assistance/")
            ? "Remote assistance"
            : pathname.includes("/recovery/")
              ? "Recovery key"
              : pathname.endsWith("/recovery-enrollment")
                ? "Recover enrollment"
                : null
      : null;
  const genericRecord =
    currentPage?.to === "/devices"
      ? "Device details"
      : currentPage?.to === "/secrets"
        ? "Secret details"
        : currentPage?.to === "/settings"
          ? pathname.endsWith("/assistant-access")
            ? "Assistant access"
            : "Device capabilities"
          : pathname.endsWith("/new")
            ? "Create profile"
            : "Profile details";

  const togglePages = useCallback(() => {
    // The shortcut can hide a focused page link. Return focus to the persistent control first.
    if (pagesOpen && pagesColumn.current?.contains(document.activeElement)) {
      collapseButton.current?.focus();
    }
    const next = !pagesOpen;
    setPagesOpen(next);
    setAnnouncement(next ? "Page navigation shown." : "Page navigation hidden.");
    try {
      localStorage.setItem(preferenceKey, next ? "expanded" : "collapsed");
    } catch {
      // The current tab still remembers the preference until it closes.
    }
  }, [pagesOpen, preferenceKey]);

  useEffect(() => {
    function shortcut(event: KeyboardEvent) {
      if (
        event.defaultPrevented ||
        event.altKey ||
        event.shiftKey ||
        !(event.ctrlKey || event.metaKey) ||
        event.key.toLowerCase() !== "b" ||
        !matchMedia("(min-width: 768px)").matches ||
        document.querySelector('[role="dialog"]') ||
        document.fullscreenElement
      )
        return;
      const target = event.target;
      if (
        target instanceof HTMLElement &&
        (target.isContentEditable || target.matches("input, textarea, select"))
      )
        return;
      event.preventDefault();
      togglePages();
    }
    window.addEventListener("keydown", shortcut);
    return () => window.removeEventListener("keydown", shortcut);
  }, [togglePages]);

  function pageLinks(list: typeof items, closeMobile = false) {
    return list.map((item) => (
      <Link
        key={item.to}
        to={item.to}
        aria-current={
          pathname === item.to || pathname.startsWith(`${item.to}/`) ? "page" : undefined
        }
        className={pageLinkClass}
        onClick={closeMobile ? () => setMobileOpen(false) : undefined}
      >
        <span>{item.label}</span>
      </Link>
    ));
  }

  const account = (mobile = false) => (
    <Menu.Root>
      <Menu.Trigger
        aria-label={`Account menu for ${userLabel}`}
        render={
          <Button
            variant="ghost"
            className={mobile ? "h-auto w-full justify-start gap-3 px-3 py-3" : "size-11 p-0"}
          />
        }
      >
        <span className="flex size-8 shrink-0 items-center justify-center border bg-background text-sm font-semibold">
          {userLabel.slice(0, 2).toUpperCase()}
        </span>
        {mobile ? (
          <span className="grid min-w-0 gap-1 text-left">
            <span className="wrap-anywhere">{userLabel}</span>
            <span className="text-xs text-muted-foreground">{roleLabel(role)}</span>
          </span>
        ) : null}
      </Menu.Trigger>
      <Menu.Portal>
        <Menu.Positioner
          side={mobile ? "top" : "right"}
          align="end"
          sideOffset={8}
          className="z-50"
        >
          <Menu.Popup className="min-w-56 border bg-popover p-1 text-sm text-popover-foreground shadow-lg outline-none">
            <div className="grid gap-2 border-b p-3">
              <span className="max-w-64 wrap-anywhere font-medium">{userLabel}</span>
              {principal.breakGlass ? (
                <StatusBadge status="warning">Break-glass session</StatusBadge>
              ) : (
                <Badge variant="secondary">{roleLabel(role)}</Badge>
              )}
            </div>
            <Menu.Item
              disabled={loggingOut}
              onClick={onLogout}
              className="flex cursor-default items-center gap-2 px-3 py-2 outline-none data-highlighted:bg-selection data-disabled:opacity-50"
            >
              <LogOutIcon className="size-4" />
              {loggingOut ? "Signing out…" : "Sign out"}
            </Menu.Item>
          </Menu.Popup>
        </Menu.Positioner>
      </Menu.Portal>
    </Menu.Root>
  );

  return (
    <TooltipProvider>
      <div
        className="flex min-h-svh w-full bg-background"
        data-shell
        data-pages-state={pagesOpen ? "expanded" : "collapsed"}
      >
        <aside
          data-shell-rail-column
          className="hidden w-[76px] shrink-0 border-r bg-sidebar text-sidebar-foreground md:block"
        >
          <div
            data-shell-rail
            className="sticky top-0 flex h-svh flex-col items-center px-1.5 py-5"
          >
            <div
              data-sidebar-logo
              className="mb-6 flex size-9 shrink-0 items-center justify-center"
            >
              <BrandLogo compact className="size-9" />
            </div>
            <nav
              aria-label="Main navigation"
              className="flex min-h-0 w-full flex-1 flex-col gap-1 overflow-y-auto"
            >
              {areas
                .filter((entry) => entry.label !== "Settings")
                .map((entry) => (
                  <Link
                    key={entry.label}
                    to={items.find((item) => item.group === entry.label)!.to}
                    data-work-area={entry.label}
                    aria-current={area === entry.label ? "true" : undefined}
                    className="flex min-h-16 shrink-0 flex-col items-center justify-center gap-1 border-l-2 border-transparent text-xs text-sidebar-foreground/80 outline-none hover:bg-sidebar-accent focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring aria-current:border-primary aria-current:bg-sidebar-accent aria-current:text-primary"
                  >
                    <entry.icon className="size-5" aria-hidden="true" />
                    <span>{entry.label}</span>
                  </Link>
                ))}
              {areas.some((entry) => entry.label === "Settings") ? (
                <Link
                  to="/settings"
                  data-work-area="Settings"
                  aria-current={area === "Settings" ? "true" : undefined}
                  className="mt-auto flex min-h-16 shrink-0 flex-col items-center justify-center gap-1 border-l-2 border-transparent text-xs text-sidebar-foreground/80 outline-none hover:bg-sidebar-accent focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring aria-current:border-primary aria-current:bg-sidebar-accent aria-current:text-primary"
                >
                  <SettingsIcon className="size-5" aria-hidden="true" />
                  <span>Settings</span>
                </Link>
              ) : null}
            </nav>
            <div className="mt-auto w-full border-t pt-3 text-center">{account()}</div>
          </div>
        </aside>
        <nav
          id="page-navigation"
          ref={pagesColumn}
          aria-label={`${area} pages`}
          data-shell-pages
          hidden={!pagesOpen}
          className={`w-52 shrink-0 border-r bg-sidebar text-sidebar-foreground ${pagesOpen ? "hidden md:block" : "hidden"}`}
        >
          <div className="sticky top-0 flex h-svh flex-col overflow-y-auto px-3 py-6">
            <h2 className="px-3 pb-4 text-base font-semibold">{area}</h2>
            {pageLinks(pages)}
            {related.length > 0 ? (
              <>
                <h3 className="px-3 pt-6 pb-2 text-xs font-medium text-muted-foreground">
                  Related work
                </h3>
                {related.map((item) => (
                  <Link key={item.to} to={item.to} className={pageLinkClass}>
                    <span>{item.label}</span>
                    <ArrowUpRightIcon className="ml-auto size-3.5" aria-hidden="true" />
                  </Link>
                ))}
              </>
            ) : null}
          </div>
        </nav>
        <div className="flex min-w-0 flex-1 flex-col">
          <header className="sticky top-0 z-30 flex h-16 shrink-0 items-center gap-2 border-b bg-background px-4 md:gap-3 md:px-7">
            <Sheet open={mobileOpen} onOpenChange={setMobileOpen}>
              <SheetTrigger
                aria-label="Toggle navigation"
                render={<Button variant="ghost" size="icon" className="shrink-0 md:hidden" />}
              >
                <MenuIcon />
              </SheetTrigger>
              <SheetContent
                side="left"
                className="max-w-[calc(100vw-2rem)] gap-0 bg-sidebar p-0 text-sidebar-foreground data-[side=left]:w-80"
              >
                <SheetHeader className="border-b">
                  <SheetTitle>Navigation</SheetTitle>
                  <SheetDescription className="sr-only">Choose a page.</SheetDescription>
                </SheetHeader>
                <nav aria-label="Main navigation" className="min-h-0 flex-1 overflow-y-auto p-3">
                  <h2 className="px-3 pt-2 pb-3 text-base font-semibold">{area}</h2>
                  {pageLinks(pages, true)}
                  {related.length > 0 ? (
                    <>
                      <h3 className="px-3 pt-5 pb-2 text-xs font-medium text-muted-foreground">
                        Related work
                      </h3>
                      {pageLinks(related, true)}
                    </>
                  ) : null}
                  <h3 className="px-3 pt-6 pb-2 text-xs font-medium text-muted-foreground">
                    Other areas
                  </h3>
                  {areas
                    .filter((entry) => entry.label !== area)
                    .map((entry) => (
                      <details key={entry.label} className="group/area">
                        <summary className={`${pageLinkClass} cursor-pointer list-none`}>
                          <entry.icon className="size-4" aria-hidden="true" />
                          <span>{entry.label}</span>
                          <ChevronDownIcon
                            className="ml-auto size-4 group-open/area:rotate-180"
                            aria-hidden="true"
                          />
                        </summary>
                        <div className="pl-6">
                          {pageLinks(
                            items.filter((item) => item.group === entry.label),
                            true,
                          )}
                        </div>
                      </details>
                    ))}
                  <div className="mt-6 border-t pt-3">{account(true)}</div>
                </nav>
              </SheetContent>
            </Sheet>
            <Tooltip>
              <TooltipTrigger
                render={
                  <Button
                    ref={collapseButton}
                    variant="ghost"
                    size="icon"
                    className="hidden shrink-0 md:inline-flex"
                    aria-label="Toggle page navigation"
                    aria-expanded={pagesOpen}
                    aria-controls="page-navigation"
                    aria-keyshortcuts="Control+b Meta+b"
                    onClick={togglePages}
                  />
                }
              >
                {pagesOpen ? <PanelLeftCloseIcon /> : <PanelLeftOpenIcon />}
              </TooltipTrigger>
              <TooltipContent>
                {pagesOpen ? "Hide page navigation" : "Show page navigation"} (Control or Command B)
              </TooltipContent>
            </Tooltip>
            <Breadcrumb className="min-w-0">
              <BreadcrumbList className="flex-nowrap">
                <BreadcrumbItem className="hidden md:inline-flex">
                  {pages[0] ? (
                    <BreadcrumbLink render={<Link to={pages[0].to} />}>{area}</BreadcrumbLink>
                  ) : (
                    <span>{area}</span>
                  )}
                </BreadcrumbItem>
                <BreadcrumbSeparator className="hidden md:block" />
                <BreadcrumbItem className={isDetail ? "hidden sm:inline-flex" : "min-w-0"}>
                  {isDetail && canOpenPage ? (
                    <BreadcrumbLink render={<Link to={currentPage.to} />}>{title}</BreadcrumbLink>
                  ) : isDetail ? (
                    <span className="truncate">{title}</span>
                  ) : (
                    <BreadcrumbPage className="truncate">{title}</BreadcrumbPage>
                  )}
                </BreadcrumbItem>
                {isDetail && canOpenPage && subPage && recordTitle && deviceId ? (
                  <>
                    <BreadcrumbSeparator className="hidden sm:block" />
                    <BreadcrumbItem className="hidden min-w-0 sm:inline-flex">
                      <BreadcrumbLink
                        className="truncate"
                        render={<Link to="/devices/$deviceId" params={{ deviceId }} />}
                      >
                        {recordTitle}
                      </BreadcrumbLink>
                    </BreadcrumbItem>
                  </>
                ) : null}
                {isDetail ? (
                  <>
                    <BreadcrumbSeparator className="hidden sm:block" />
                    <BreadcrumbItem className="min-w-0">
                      <BreadcrumbPage className="truncate">
                        {subPage ?? recordTitle ?? genericRecord}
                      </BreadcrumbPage>
                    </BreadcrumbItem>
                  </>
                ) : null}
              </BreadcrumbList>
            </Breadcrumb>
            <div className="ml-auto flex shrink-0 items-center gap-1">
              {commandPalette}
              <ThemeToggle />
            </div>
          </header>
          <div className="mx-auto flex w-full max-w-[1600px] min-w-0 flex-1 flex-col gap-6 p-4 md:px-7 md:py-6">
            <BreadcrumbTitleContext value={setRecordTitle}>{children}</BreadcrumbTitleContext>
          </div>
        </div>
      </div>
      <span className="sr-only" role="status" aria-live="polite">
        {announcement}
      </span>
    </TooltipProvider>
  );
}
