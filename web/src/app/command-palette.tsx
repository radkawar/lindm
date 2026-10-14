// SPDX-License-Identifier: Apache-2.0

import { useDeferredValue, useEffect, useRef, useState } from "react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { ArrowLeftIcon, MonitorIcon, SearchIcon } from "lucide-react";
import { DeviceState } from "../../gen/lindm/admin/v1/admin_pb";
import type { SessionPrincipal } from "../../gen/lindm/auth/v1/auth_pb";
import type { AuthLifetime } from "@/lib/auth-lifetime";
import { canPermission } from "@/lib/permissions";
import { toRpcFailure } from "@/lib/errors";
import { RpcError } from "@/components/ui/rpc-error";
import { DeviceLifecycleBadge } from "@/features/devices/lifecycle-badge";
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
import { paletteActions, paletteDeviceActions, type PaletteDeviceAction } from "./palette-actions";

export function CommandPalette({
  principal,
  lifetime,
}: {
  principal: SessionPrincipal;
  lifetime: AuthLifetime;
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  // Set while the palette asks which device a chosen device action is for.
  const [deviceAction, setDeviceAction] = useState<PaletteDeviceAction | null>(null);
  const returnFocus = useRef<HTMLElement | null>(null);
  const navigate = useNavigate();
  const canReadFleet = canPermission(principal, "fleet.read");
  // Hostname prefix search runs on the server, so every authorized device can be found.
  const namePrefix = useDeferredValue(query.trim());
  const searchDevices = open && canReadFleet && (deviceAction !== null || namePrefix !== "");
  const devices = useQuery({
    ...devicesQueryOptions(lifetime, {
      pageSize: 50,
      pageToken: "",
      filter: namePrefix ? JSON.stringify({ namePrefix }) : "",
    }),
    placeholderData: keepPreviousData,
    enabled: searchDevices,
  });
  const deviceResults = searchDevices ? (devices.data?.devices ?? []) : [];
  const actions = paletteActions.filter((action) => action.allowed(principal));
  const deviceActions = paletteDeviceActions.filter((action) => action.allowed(principal));

  function changeOpen(next: boolean) {
    setOpen(next);
    if (next) return;
    setQuery("");
    setDeviceAction(null);
  }
  function run(go: () => Promise<void>) {
    changeOpen(false);
    void go();
  }
  function chooseDeviceAction(action: PaletteDeviceAction | null) {
    setDeviceAction(action);
    setQuery("");
  }

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (
        event.defaultPrevented ||
        document.fullscreenElement?.hasAttribute("data-assistance-fullscreen")
      )
        return;
      // A shortcut must not stack a second modal over navigation or a task dialog.
      if (!open && document.querySelector('[role="dialog"][data-open]')) return;
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        // Typing in a form field keeps the shortcut out of the way; the palette's own
        // search box still closes it.
        const target = event.target;
        if (
          target instanceof HTMLElement &&
          (target.isContentEditable ||
            target.matches(
              "textarea, select, input:not([type=checkbox], [type=radio], [type=button], [type=submit], [type=reset])",
            )) &&
          !target.closest("[cmdk-root]")
        )
          return;
        event.preventDefault();
        const active = document.activeElement;
        if (active instanceof HTMLElement && !active.closest('[role="dialog"]'))
          returnFocus.current = active;
        // Opening and closing both start from all commands with an empty search.
        setQuery("");
        setDeviceAction(null);
        setOpen((value) => !value);
      }
    }
    // The palette portals outside assistance's fullscreen subtree. Close it on
    // entry instead of leaving an invisible modal trapping the safety toolbar.
    function onFullscreenChange() {
      if (document.fullscreenElement?.hasAttribute("data-assistance-fullscreen")) setOpen(false);
    }
    document.addEventListener("keydown", onKeyDown);
    document.addEventListener("fullscreenchange", onFullscreenChange);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      document.removeEventListener("fullscreenchange", onFullscreenChange);
    };
  }, [open]);

  const searched = query.trim();
  const emptyText = deviceAction
    ? searched
      ? `No device hostnames start with “${searched}”.`
      : "No devices yet."
    : canReadFleet
      ? `No pages, actions or devices match “${searched}”.`
      : `No pages or actions match “${searched}”.`;

  return (
    <>
      <Button
        variant="outline"
        size="sm"
        className="h-9 gap-2 text-muted-foreground md:min-w-56 md:justify-start"
        onClick={(event) => {
          returnFocus.current = event.currentTarget;
          changeOpen(true);
        }}
        aria-keyshortcuts="Control+k Meta+k"
        aria-haspopup="dialog"
      >
        <SearchIcon />
        <span className="sm:hidden">Find</span>
        <span className="hidden sm:inline">Find a page or device</span>
        <kbd className="ml-auto hidden border px-1 text-xs md:inline">Ctrl / ⌘ K</kbd>
      </Button>
      <CommandDialog
        open={open}
        onOpenChange={changeOpen}
        finalFocus={returnFocus}
        title="Search console"
        description="Choose a page, action or device. Use arrow keys to choose. Press Enter to open."
        className="sm:max-w-xl"
      >
        {/* The server already matched the hostname prefix while a device is being chosen. */}
        <Command
          shouldFilter={deviceAction === null}
          // Every typed word must appear in the label or keywords; cmdk's default
          // letter-by-letter match lists unrelated commands ("wipe" found New profile).
          filter={(value, search, keywords) => {
            const haystack = [value, ...(keywords ?? [])].join(" ").toLowerCase();
            const words = search.toLowerCase().split(/\s+/).filter(Boolean);
            if (!words.every((word) => haystack.includes(word))) return 0;
            return value.toLowerCase().startsWith(words[0] ?? "") ? 1 : 0.5;
          }}
        >
          {deviceAction ? (
            <div className="flex min-w-0 items-center gap-2 px-1 pt-1">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => chooseDeviceAction(null)}
                aria-label="Back to all commands"
              >
                <ArrowLeftIcon aria-hidden="true" />
                Back
              </Button>
              <p className="min-w-0 break-words text-sm font-medium">{deviceAction.prompt}</p>
            </div>
          ) : null}
          <CommandInput
            value={query}
            onValueChange={setQuery}
            onKeyDown={(event) => {
              if (deviceAction && event.key === "Backspace" && query === "") {
                event.preventDefault();
                chooseDeviceAction(null);
              }
            }}
            placeholder={deviceAction ? "Search by hostname…" : "Search pages, actions or devices…"}
            aria-label={
              deviceAction
                ? `${deviceAction.prompt}: search by hostname`
                : "Search pages, actions and devices"
            }
          />
          <CommandList>
            <CommandEmpty>
              {searchDevices && devices.isFetching ? "Searching devices…" : emptyText}
            </CommandEmpty>
            {deviceAction ? null : (
              <>
                <CommandGroup heading="Pages">
                  {visibleNavigation(principal).map((item) => (
                    <CommandItem
                      key={item.to}
                      value={item.label}
                      onSelect={() => run(() => navigate({ to: item.to }))}
                    >
                      <item.icon />
                      {item.label}
                    </CommandItem>
                  ))}
                </CommandGroup>
                {actions.length || deviceActions.length ? (
                  <CommandGroup heading="Actions">
                    {deviceActions.map((action) => (
                      <CommandItem
                        key={action.id}
                        value={action.label}
                        keywords={action.keywords}
                        onSelect={() => chooseDeviceAction(action)}
                      >
                        <action.icon />
                        {action.label}
                      </CommandItem>
                    ))}
                    {actions.map((action) => (
                      <CommandItem
                        key={action.id}
                        value={action.label}
                        keywords={action.keywords}
                        onSelect={() => run(() => action.open(navigate))}
                      >
                        <action.icon />
                        {action.label}
                      </CommandItem>
                    ))}
                  </CommandGroup>
                ) : null}
              </>
            )}
            {deviceResults.length ? (
              <CommandGroup heading="Devices">
                {deviceResults.map((device) => {
                  const name = device.hostname.trim() || "Unnamed device";
                  // Device actions apply only to enrolled devices; others stay visible with their state.
                  const unavailable =
                    deviceAction !== null && device.lifecycleState !== DeviceState.ACTIVE;
                  return (
                    <CommandItem
                      key={device.id}
                      value={`${device.hostname} ${device.id}`}
                      disabled={unavailable}
                      onSelect={() =>
                        run(() =>
                          deviceAction
                            ? deviceAction.open(navigate, device.id)
                            : navigate({
                                to: "/devices/$deviceId",
                                params: { deviceId: device.id },
                              }),
                        )
                      }
                    >
                      <MonitorIcon />
                      <span className="min-w-0 flex-1 break-words">{name}</span>{" "}
                      {unavailable ? (
                        <DeviceLifecycleBadge state={device.lifecycleState} />
                      ) : (
                        <span className="text-xs text-muted-foreground">
                          {device.osName ||
                            [device.osId, device.osVersion].filter(Boolean).join(" ")}
                        </span>
                      )}
                    </CommandItem>
                  );
                })}
              </CommandGroup>
            ) : null}
          </CommandList>
          {/* Status and errors stay outside the listbox, which may only contain options. */}
          {searchDevices && devices.data?.nextPageToken ? (
            <p className="px-3 py-2 text-xs text-muted-foreground" role="status">
              More devices match. Type more of the hostname to narrow the list.
            </p>
          ) : null}
          {searchDevices && devices.isError ? (
            <RpcError failure={toRpcFailure(devices.error)} title="Device search unavailable" />
          ) : null}
          <div className="flex items-center justify-end gap-2 border-t px-3 py-2 text-xs text-muted-foreground sm:justify-between">
            {/* Keyboard hints only where a keyboard is likely. */}
            <span className="hidden sm:inline">
              ↑ ↓ Navigate · Enter Open{deviceAction ? " · Backspace Back" : ""} · Esc Close
            </span>
            <Button variant="ghost" size="sm" onClick={() => changeOpen(false)}>
              Close
            </Button>
          </div>
        </Command>
      </CommandDialog>
    </>
  );
}
