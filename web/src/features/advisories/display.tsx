import type { Timestamp } from "@bufbuild/protobuf/wkt";
import { useEffect, useState } from "react";
import { AdvisoryFindingState } from "../../../gen/lindm/admin/v1/advisories_pb";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { toRpcFailure } from "@/lib/errors";

export function useFreshnessClock() {
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);
  return now;
}
export function unexpired(expiry: Timestamp | undefined, now: number) {
  return expiry !== undefined && Number(expiry.seconds) * 1000 + expiry.nanos / 1_000_000 > now;
}
export function findingStateLabel(state: AdvisoryFindingState) {
  return AdvisoryFindingState[state] === "UNSPECIFIED"
    ? "UNKNOWN"
    : (AdvisoryFindingState[state] ?? "UNKNOWN");
}
export function ReadFailure({ error }: { error: unknown }) {
  const failure = toRpcFailure(error);
  return (
    <Alert variant="destructive">
      <AlertTitle>{failure.denied ? "Not authorized" : "UNKNOWN — data unavailable"}</AlertTitle>
      <AlertDescription>
        {failure.codeName}: {failure.message}
      </AlertDescription>
    </Alert>
  );
}
export function AdvisoryPaging({
  token,
  next,
  busy,
  onPage,
}: {
  token: string;
  next: string;
  busy: boolean;
  onPage: (token: string) => void;
}) {
  return (
    <div className="flex flex-wrap gap-2">
      <Button variant="outline" disabled={!token || busy} onClick={() => onPage("")}>
        First page
      </Button>
      <Button variant="outline" disabled={!next || busy} onClick={() => onPage(next)}>
        Next page
      </Button>
    </div>
  );
}
