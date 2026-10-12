import { createFileRoute } from "@tanstack/react-router";
import { useDeviceBreadcrumbTitle } from "@/features/devices/breadcrumb";
import { DeviceActionCreatePage } from "@/features/devices/action-pages";
import { complexActionKinds, type ComplexActionKind } from "@/features/devices/action-menu";
import { canonicalUuid } from "@/lib/ids";

export const Route = createFileRoute("/_authenticated/devices_/$deviceId_/actions/new/$kind")({
  params: {
    parse: ({ deviceId, kind }) => {
      const id = canonicalUuid(deviceId);
      if (!id || id === "00000000-0000-0000-0000-000000000000")
        throw new Error("The device URL must contain a valid device ID.");
      if (!complexActionKinds.includes(kind as ComplexActionKind))
        throw new Error("This device action is not supported.");
      return { deviceId: id, kind: kind as ComplexActionKind };
    },
  },
  validateSearch: (search: Record<string, unknown>): { luksUuid: string } => {
    if (search.luksUuid === undefined || search.luksUuid === "") return { luksUuid: "" };
    const luksUuid = typeof search.luksUuid === "string" ? canonicalUuid(search.luksUuid) : null;
    if (!luksUuid) throw new Error("Select a valid LUKS volume UUID.");
    return { luksUuid };
  },
  component: ActionCreateRoute,
});

function ActionCreateRoute() {
  const { deviceId, kind } = Route.useParams();
  useDeviceBreadcrumbTitle(deviceId);
  const { luksUuid } = Route.useSearch();
  return <DeviceActionCreatePage deviceId={deviceId} kind={kind} luksUuid={luksUuid} />;
}
