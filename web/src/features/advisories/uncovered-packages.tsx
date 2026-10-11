import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { AdvisoryFindingState } from "../../../gen/lindm/admin/v1/advisories_pb";
import { RpcError } from "@/components/ui/rpc-error";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { toRpcFailure } from "@/lib/errors";
import { AdvisoryPaging, uncoveredPackageReasonText } from "./display";
import { deviceUncoveredPackagesQueryOptions } from "./queries";

// Packages of a PARTIAL evaluation whose exposure is unknown, each with the
// reason the applied feed does not cover it. Never shown as unaffected.
export function UncoveredPackages({ deviceId }: { deviceId: string }) {
  const lifetime = useAuthLifetime();
  const [pageToken, setPageToken] = useState("");
  const uncovered = useQuery(deviceUncoveredPackagesQueryOptions(lifetime, deviceId, pageToken));
  const freshness = uncovered.data?.freshness;
  return (
    <section className="grid gap-3" aria-busy={uncovered.isFetching}>
      <h3 className="font-semibold">Packages with unknown exposure</h3>
      {uncovered.isPending ? (
        <div role="status" className="grid gap-2">
          <span className="text-sm text-muted-foreground">Loading uncovered packages…</span>
          <Skeleton className="h-24 w-full" />
        </div>
      ) : null}
      {uncovered.error ? <RpcError failure={toRpcFailure(uncovered.error)} /> : null}
      {freshness && freshness.state !== AdvisoryFindingState.PARTIAL ? (
        <p className="text-sm text-muted-foreground">
          The evaluation changed; refresh the advisory findings.
        </p>
      ) : null}
      {uncovered.data?.packages.length ? (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Package</TableHead>
              <TableHead>Installed version</TableHead>
              <TableHead>Exposure unknown because</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {uncovered.data.packages.map((pkg) => (
              <TableRow key={`${pkg.name}/${pkg.architecture}/${pkg.version}`}>
                <TableCell className="break-all">
                  {pkg.name} ({pkg.architecture || "architecture unavailable"})
                </TableCell>
                <TableCell className="break-all">{pkg.version}</TableCell>
                <TableCell>
                  {uncoveredPackageReasonText(pkg.reason, freshness?.reason ?? "")}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      ) : null}
      <AdvisoryPaging
        token={pageToken}
        next={uncovered.data?.nextPageToken ?? ""}
        busy={uncovered.isFetching}
        onPage={setPageToken}
      />
    </section>
  );
}
