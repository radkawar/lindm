import { useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useRouter } from "@tanstack/react-router";
import { MonitorIcon, SearchIcon } from "lucide-react";
import type { SessionPrincipal } from "../../gen/lindm/auth/v1/auth_pb";
import type { AuthLifetime } from "@/lib/auth-lifetime";
import { canPermission } from "@/lib/permissions";
import { toRpcFailure } from "@/lib/errors";
import { RpcError } from "@/components/ui/rpc-error";
import { devicesQueryOptions } from "@/features/devices/queries";
import { visibleNavigation } from "@/components/layout/navigation";
import { Button } from "@/components/ui/button";
import {
  Command,
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command";

export function CommandPalette({
  principal,
  lifetime,
}: {
  principal: SessionPrincipal;
  lifetime: AuthLifetime;
}) {
  const [open, setOpen] = useState(false);
  const returnFocus = useRef<HTMLElement | null>(null);
  const router = useRouter();
  const devices = useQuery({
    ...devicesQueryOptions(lifetime, { pageSize: 200, pageToken: "", filter: "" }),
    enabled: open && canPermission(principal, "fleet.read"),
  });
  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        const active = document.activeElement;
        if (active instanceof HTMLElement && !active.closest('[role="dialog"]'))
          returnFocus.current = active;
        setOpen((value) => !value);
      }
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, []);
  return (
    <>
      <Button
        variant="outline"
        size="sm"
        className="gap-2 text-muted-foreground"
        onClick={(event) => {
          returnFocus.current = event.currentTarget;
          setOpen(true);
        }}
        aria-label="Search pages and devices (Control or Command K)"
        aria-haspopup="dialog"
      >
        <SearchIcon />
        <span className="hidden sm:inline">Search console</span>
        <kbd className="hidden border px-1 text-[10px] md:inline">⌘ K</kbd>
      </Button>
      <CommandDialog
        open={open}
        onOpenChange={setOpen}
        finalFocus={returnFocus}
        title="Search console"
        description="Find a page or a device. Use arrow keys to choose and Enter to open."
        className="sm:max-w-xl"
      >
        <Command>
          <CommandInput
            placeholder="Search pages, device names, or IDs…"
            aria-label="Search pages and devices"
          />
          <CommandList>
            <CommandEmpty>No matching pages or loaded devices.</CommandEmpty>
            <CommandGroup heading="Navigation">
              {visibleNavigation(principal).map((item) => (
                <CommandItem
                  key={item.to}
                  value={item.label}
                  onSelect={() => {
                    setOpen(false);
                    void router.navigate({ to: item.to });
                  }}
                >
                  <item.icon />
                  {item.label}
                </CommandItem>
              ))}
            </CommandGroup>
            {canPermission(principal, "fleet.read") && !devices.isError && devices.data ? (
              <CommandGroup heading="Devices · first 200 authorized devices">
                {devices.data.devices.map((device) => (
                  <CommandItem
                    key={device.id}
                    value={`${device.hostname} ${device.id}`}
                    onSelect={() => {
                      setOpen(false);
                      void router.navigate({
                        to: "/devices/$deviceId",
                        params: { deviceId: device.id },
                      });
                    }}
                  >
                    <MonitorIcon />
                    <span className="min-w-0 truncate">
                      {device.hostname.trim() || "Unnamed device"}
                    </span>
                  </CommandItem>
                ))}
              </CommandGroup>
            ) : null}
          </CommandList>
          {/* Status and errors stay outside the listbox, which may only contain options. */}
          {canPermission(principal, "fleet.read") && devices.isPending ? (
            <p className="px-3 py-2 text-xs text-muted-foreground" role="status">
              Loading device search…
            </p>
          ) : null}
          {canPermission(principal, "fleet.read") && devices.isError ? (
            <RpcError failure={toRpcFailure(devices.error)} title="Device search unavailable" />
          ) : null}
          <div className="flex items-center justify-between gap-2 border-t px-3 py-2 text-xs text-muted-foreground">
            <span>↑ ↓ Navigate · Enter Open · Esc Close</span>
            <Button variant="ghost" size="sm" onClick={() => setOpen(false)}>
              Close
            </Button>
          </div>
        </Command>
      </CommandDialog>
    </>
  );
}
