// Adapted from the official shadcn/ui sidebar-07 block (MIT; web/LICENSE.shadcn).
import { Link, useRouterState } from "@tanstack/react-router";
import { ChevronDownIcon, ChevronsUpDownIcon, LogOutIcon, ShieldCheckIcon } from "lucide-react";
import { useState, type ReactNode } from "react";
import type { SessionPrincipal } from "../../../gen/lindm/auth/v1/auth_pb";
import { ThemeToggle } from "./theme-toggle";
import { navigation, visibleNavigation } from "./navigation";
import { Badge } from "@/components/ui/badge";
import { StatusBadge } from "@/components/ui/status-badge";
import { Menu } from "@base-ui/react/menu";
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbLink,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarRail,
  SidebarTrigger,
  useSidebar,
} from "@/components/ui/sidebar";

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
  const currentPage = navigation.find(
    (item) => pathname === item.to || pathname.startsWith(`${item.to}/`),
  );
  const title = currentPage?.label ?? "Console";
  const isDetail = currentPage && pathname !== currentPage.to;
  return (
    <SidebarProvider>
      <Sidebar collapsible="icon">
        <SidebarHeader className="border-b px-3 py-5">
          <div className="flex items-center gap-3">
            <div className="flex size-8 shrink-0 items-center justify-center bg-primary text-primary-foreground">
              <ShieldCheckIcon className="size-5" />
            </div>
            <div className="grid group-data-[collapsible=icon]:hidden">
              <span className="text-lg leading-none font-semibold tracking-tight">lindm</span>
              <span className="mt-1 text-xs text-muted-foreground">Linux device management</span>
            </div>
          </div>
        </SidebarHeader>
        <SidebarContent className="py-3">
          <nav aria-label="Main navigation">
            {(["Fleet", "Security", "Administration"] as const).map((group) => (
              <NavigationGroup
                key={group}
                group={group}
                pathname={pathname}
                principal={principal}
              />
            ))}
          </nav>
        </SidebarContent>
        <SidebarFooter className="border-t p-3">
          <Menu.Root>
            <Menu.Trigger
              aria-label={`Account menu for ${userLabel}`}
              render={<Button variant="ghost" className="h-auto w-full justify-start px-1 py-2" />}
            >
              <span className="flex size-8 shrink-0 items-center justify-center border bg-background text-sm font-semibold">
                {userLabel.slice(0, 2).toUpperCase()}
              </span>
              <span className="grid min-w-0 flex-1 gap-1 text-left group-data-[collapsible=icon]:hidden">
                <span className="truncate text-sm font-medium">{userLabel}</span>
                <span className="truncate text-xs text-muted-foreground">{role || "No role"}</span>
              </span>
              <ChevronsUpDownIcon className="size-4 group-data-[collapsible=icon]:hidden" />
            </Menu.Trigger>
            <Menu.Portal>
              <Menu.Positioner side="top" align="start" sideOffset={8} className="z-50">
                <Menu.Popup className="min-w-56 border bg-popover p-1 text-sm text-popover-foreground shadow-lg outline-none">
                  <div className="grid gap-2 border-b p-3">
                    <span className="max-w-64 truncate font-medium">{userLabel}</span>
                    {principal.breakGlass ? (
                      <StatusBadge status="warning">Break-glass session</StatusBadge>
                    ) : (
                      <Badge variant="secondary">{role || "No role"}</Badge>
                    )}
                  </div>
                  <Menu.Item
                    disabled={loggingOut}
                    onClick={onLogout}
                    className="flex cursor-default items-center gap-2 px-3 py-2 outline-none data-highlighted:bg-accent data-disabled:opacity-50"
                  >
                    <LogOutIcon className="size-4" />
                    {loggingOut ? "Signing out…" : "Sign out"}
                  </Menu.Item>
                </Menu.Popup>
              </Menu.Positioner>
            </Menu.Portal>
          </Menu.Root>
        </SidebarFooter>
        <SidebarRail />
      </Sidebar>
      <SidebarInset className="min-w-0">
        <header className="sticky top-0 z-30 flex h-16 shrink-0 items-center gap-2 border-b bg-background/95 px-4 backdrop-blur-sm md:px-6">
          <SidebarTrigger className="-ml-1" />
          <Separator
            orientation="vertical"
            className="mr-2 data-vertical:h-4 data-vertical:self-auto"
          />
          <Breadcrumb className="min-w-0">
            <BreadcrumbList className="flex-nowrap">
              <BreadcrumbItem className={isDetail ? "hidden sm:inline-flex" : "min-w-0"}>
                {isDetail ? (
                  <BreadcrumbLink render={<Link to={currentPage.to} />}>{title}</BreadcrumbLink>
                ) : (
                  <BreadcrumbPage className="truncate">{title}</BreadcrumbPage>
                )}
              </BreadcrumbItem>
              {isDetail ? (
                <>
                  <BreadcrumbSeparator className="hidden sm:block" />
                  <BreadcrumbItem>
                    <BreadcrumbPage>
                      {currentPage.to === "/devices"
                        ? pathname.includes("/actions/new/")
                          ? "New action"
                          : pathname.includes("/actions/")
                            ? "Action status"
                            : pathname.includes("/recovery/")
                              ? "Recovery key"
                              : pathname.endsWith("/recovery-enrollment")
                                ? "Recover enrollment"
                                : "Device details"
                        : currentPage.to === "/secrets"
                          ? "Secret details"
                          : pathname.endsWith("/new")
                            ? "Create profile"
                            : "Profile details"}
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
        <div className="flex min-w-0 flex-1 flex-col gap-6 p-4 md:p-6 lg:p-8">{children}</div>
      </SidebarInset>
    </SidebarProvider>
  );
}

function NavigationGroup({
  group,
  pathname,
  principal,
}: {
  group: string;
  pathname: string;
  principal: SessionPrincipal;
}) {
  const { setOpenMobile, state, isMobile } = useSidebar();
  const iconOnly = state === "collapsed" && !isMobile;
  const [expanded, setExpanded] = useState(true);
  const items = visibleNavigation(principal).filter((item) => item.group === group);
  if (items.length === 0) return null;
  return (
    <SidebarGroup>
      <SidebarGroupLabel
        render={
          <button
            type="button"
            tabIndex={iconOnly ? -1 : 0}
            aria-hidden={iconOnly}
            aria-expanded={expanded}
            onClick={() => setExpanded(!expanded)}
          />
        }
        className="mb-1 flex w-full justify-between text-[11px] font-semibold tracking-wider uppercase"
      >
        {group}
        <ChevronDownIcon
          className={`size-3 transition-transform ${expanded ? "" : "-rotate-90"}`}
        />
      </SidebarGroupLabel>
      {expanded || iconOnly ? (
        <SidebarMenu>
          {items.map((item) => (
            <SidebarMenuItem key={item.to}>
              <SidebarMenuButton
                isActive={pathname === item.to || pathname.startsWith(`${item.to}/`)}
                tooltip={item.label}
                className="h-9"
                render={<Link to={item.to} onClick={() => setOpenMobile(false)} />}
              >
                <item.icon />
                <span>{item.label}</span>
              </SidebarMenuButton>
            </SidebarMenuItem>
          ))}
        </SidebarMenu>
      ) : null}
    </SidebarGroup>
  );
}
