import { Link, useRouterState } from "@tanstack/react-router";
import { ClipboardListIcon, KeyRoundIcon, LogOutIcon, MonitorIcon } from "lucide-react";
import type { ReactNode } from "react";
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbList,
  BreadcrumbPage,
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

const NAV = [
  { to: "/devices", label: "Devices", icon: MonitorIcon },
  { to: "/enrollment", label: "Enrollment", icon: KeyRoundIcon },
  { to: "/audit", label: "Audit", icon: ClipboardListIcon },
] as const;

export function ConsoleShell({
  userLabel,
  role,
  loggingOut,
  onLogout,
  children,
}: {
  userLabel: string;
  role: string;
  loggingOut: boolean;
  onLogout: () => void;
  children: ReactNode;
}) {
  const pathname = useRouterState({ select: (state) => state.location.pathname });
  const title =
    NAV.find((item) => pathname === item.to || pathname.startsWith(`${item.to}/`))?.label ??
    "Control plane";
  return (
    <SidebarProvider>
      <Sidebar collapsible="icon">
        <SidebarHeader>
          <div className="px-2 py-1 text-sm font-medium group-data-[collapsible=icon]:hidden">
            lindm
          </div>
        </SidebarHeader>
        <SidebarContent>
          <SidebarGroup>
            <SidebarGroupLabel>Control plane</SidebarGroupLabel>
            <NavigationMenu pathname={pathname} />
          </SidebarGroup>
        </SidebarContent>
        <SidebarFooter>
          <div className="grid gap-1 px-2 text-sm group-data-[collapsible=icon]:hidden">
            <span className="truncate font-medium">{userLabel}</span>
            <span className="truncate text-xs text-muted-foreground">
              {role === "" ? "No role" : role}
            </span>
          </div>
          <Button variant="outline" disabled={loggingOut} onClick={onLogout}>
            <LogOutIcon />
            {loggingOut ? "Signing out…" : "Sign out"}
          </Button>
        </SidebarFooter>
        <SidebarRail />
      </Sidebar>
      <SidebarInset className="min-w-0">
        <header className="flex h-16 shrink-0 items-center gap-2 border-b px-4">
          <SidebarTrigger className="-ml-1" />
          <Separator
            orientation="vertical"
            className="mr-2 data-vertical:h-4 data-vertical:self-auto"
          />
          <Breadcrumb>
            <BreadcrumbList>
              <BreadcrumbItem>
                <BreadcrumbPage>{title}</BreadcrumbPage>
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
        </header>
        <div className="flex flex-1 flex-col gap-4 p-4">{children}</div>
      </SidebarInset>
    </SidebarProvider>
  );
}

function NavigationMenu({ pathname }: { pathname: string }) {
  const { setOpenMobile } = useSidebar();
  return (
    <SidebarMenu>
      {NAV.map((item) => (
        <SidebarMenuItem key={item.to}>
          <SidebarMenuButton
            isActive={pathname === item.to || pathname.startsWith(`${item.to}/`)}
            tooltip={item.label}
            render={<Link to={item.to} onClick={() => setOpenMobile(false)} />}
          >
            <item.icon />
            <span>{item.label}</span>
          </SidebarMenuButton>
        </SidebarMenuItem>
      ))}
    </SidebarMenu>
  );
}
