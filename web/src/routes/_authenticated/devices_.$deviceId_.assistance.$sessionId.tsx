import { createFileRoute } from "@tanstack/react-router";
import { AssistanceViewerPage } from "@/features/assistance/viewer";
import { canonicalUuid } from "@/lib/ids";

export const Route = createFileRoute("/_authenticated/devices_/$deviceId_/assistance/$sessionId")({
  params: {
    parse: ({ deviceId, sessionId }) => {
      const device = canonicalUuid(deviceId);
      const session = canonicalUuid(sessionId);
      if (
        !device ||
        !session ||
        device === "00000000-0000-0000-0000-000000000000" ||
        session === "00000000-0000-0000-0000-000000000000"
      )
        throw new Error("The URL must contain valid device and session IDs.");
      return { deviceId: device, sessionId: session };
    },
  },
  component: AssistanceViewerRoute,
});

function AssistanceViewerRoute() {
  const { deviceId, sessionId } = Route.useParams();
  return (
    <AssistanceViewerPage
      key={`${deviceId}:${sessionId}`}
      deviceId={deviceId}
      sessionId={sessionId}
    />
  );
}
