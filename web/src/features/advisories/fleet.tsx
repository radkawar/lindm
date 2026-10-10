import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
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
import { formatTimestamp } from "@/lib/time";
import { canonicalUuid } from "@/lib/ids";
import { AdvisoryPaging, ReadFailure, unexpired, useFreshnessClock } from "./display";
import { advisoryFeedsQueryOptions, advisorySummaryQueryOptions } from "./queries";

export function AdvisoryFleet() {
  const lifetime = useAuthLifetime();
  const [pageToken, setPageToken] = useState("");
  const now = useFreshnessClock();
  const [deviceId, setDeviceId] = useState("");
  const canonicalDeviceId = canonicalUuid(deviceId.trim());
  const summary = useQuery(advisorySummaryQueryOptions(lifetime, pageToken));
  const feeds = useQuery(advisoryFeedsQueryOptions(lifetime));
  const feedUnknown =
    !feeds.data?.feeds.length ||
    !!feeds.error ||
    feeds.data.feeds.some((feed) => !feed.fresh || !unexpired(feed.expiresAt, now));
  return (
    <div className="grid min-w-0 gap-6">
      <div className="space-y-2">
        <h1 className="text-2xl font-semibold tracking-tight">Distro advisories</h1>
        <p className="max-w-3xl text-sm text-muted-foreground">
          Distro package findings, not a complete vulnerability assessment. No findings does not
          mean clean. Stale inventory, unsupported coverage and stale feeds are UNKNOWN.
        </p>
        <Link to="/devices" className="inline-block text-sm underline underline-offset-4">
          Open devices to inspect per-device advisory findings
        </Link>
      </div>
      <Card>
        <div className="mx-6 mt-3 grid max-w-lg gap-2">
          <Label htmlFor="advisory-device-id">Open findings by device ID</Label>
          <Input
            id="advisory-device-id"
            value={deviceId}
            onChange={(event) => setDeviceId(event.target.value)}
            placeholder="Device UUID"
          />
          {canonicalDeviceId && canonicalDeviceId !== "00000000-0000-0000-0000-000000000000" ? (
            <Link
              to="/devices/$deviceId"
              params={{ deviceId: canonicalDeviceId }}
              search={{ pageSize: 50, pageToken: "", manager: "", namePrefix: "" }}
              className="underline"
            >
              Open device detail and findings
            </Link>
          ) : deviceId ? (
            <p role="status">Enter a valid nonzero device UUID.</p>
          ) : null}
        </div>
        <CardHeader>
          <CardTitle>
            <h2>Fleet summary</h2>
          </CardTitle>
          <CardDescription>
            Counts are server-evaluated. Accepted findings remain exposure, not fixes.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4">
          <Button
            className="w-fit"
            variant="outline"
            disabled={summary.isFetching}
            onClick={() => void summary.refetch()}
          >
            Refresh fleet summary
          </Button>
          {summary.isPending ? (
            <div role="status" className="grid gap-3">
              <span className="text-sm text-muted-foreground">Loading fleet summary…</span>
              <Skeleton className="h-32 w-full" />
            </div>
          ) : null}
          {summary.error ? <ReadFailure error={summary.error} /> : null}
          {feedUnknown ? (
            <Alert>
              <AlertTitle>UNKNOWN — feed coverage is not current</AlertTitle>
              <AlertDescription>
                One or more feed sources are stale or unavailable. Previously evaluated counts below
                cannot establish current fleet exposure.
              </AlertDescription>
            </Alert>
          ) : null}
          {summary.data ? (
            <>
              <dl className="grid gap-4 border bg-muted/30 p-4 sm:grid-cols-2">
                <div>
                  <dt className="text-xs text-muted-foreground">Evaluated devices</dt>
                  <dd className="mt-1 text-2xl font-semibold tabular-nums">
                    {summary.data.evaluatedDevices.toString()}
                  </dd>
                </div>
                <div>
                  <dt className="text-xs text-muted-foreground">UNKNOWN devices</dt>
                  <dd className="mt-1 text-2xl font-semibold tabular-nums">
                    {summary.data.unknownDevices.toString()}
                  </dd>
                </div>
              </dl>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Advisory / CVEs</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>Affected devices</TableHead>
                    <TableHead>Accepted devices</TableHead>
                    <TableHead>UNKNOWN devices</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {summary.data.advisories.map((advisory) => (
                    <TableRow key={advisory.advisoryId}>
                      <TableCell>
                        <p>{advisory.advisoryId}</p>
                        <p className="text-xs text-muted-foreground">
                          {advisory.cves.join(", ") || "No CVEs supplied"}
                        </p>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline">{advisory.severity || "Unknown"}</Badge>
                      </TableCell>
                      <TableCell>{advisory.affectedDevices.toString()}</TableCell>
                      <TableCell>{advisory.acceptedDevices.toString()}</TableCell>
                      <TableCell>{advisory.unknownDevices.toString()}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
              {!summary.data.advisories.length ? (
                <p
                  role="status"
                  className="border border-dashed px-4 py-8 text-center text-sm text-muted-foreground"
                >
                  No advisory summaries on this page. This does not establish that the fleet is
                  clean.
                </p>
              ) : null}
            </>
          ) : null}
          <AdvisoryPaging
            token={pageToken}
            next={summary.data?.nextPageToken ?? ""}
            busy={summary.isFetching}
            onPage={setPageToken}
          />
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>
            <h2>Feed freshness and status</h2>
          </CardTitle>
          <CardDescription>
            Feed freshness alone does not establish device inventory freshness or coverage.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4">
          <Button
            className="w-fit"
            variant="outline"
            disabled={feeds.isFetching}
            onClick={() => void feeds.refetch()}
          >
            Refresh feed status
          </Button>
          {feeds.isPending ? (
            <div role="status" className="grid gap-3">
              <span className="text-sm text-muted-foreground">Loading advisory feeds…</span>
              <Skeleton className="h-32 w-full" />
            </div>
          ) : null}
          {feeds.error ? <ReadFailure error={feeds.error} /> : null}
          {feeds.data?.feeds.length === 0 ? (
            <p
              role="status"
              className="border border-dashed px-4 py-8 text-center text-sm text-muted-foreground"
            >
              UNKNOWN — no advisory feeds configured.
            </p>
          ) : null}
          {feeds.data?.feeds.map((feed) => (
            <article key={feed.id} className="grid min-w-0 gap-2 border bg-muted/20 p-4 text-sm">
              <h3 className="break-words font-semibold">
                {feed.id} —{" "}
                {!feeds.error && feed.fresh && unexpired(feed.expiresAt, now)
                  ? "Fresh"
                  : "UNKNOWN — stale or unavailable"}
              </h3>
              <p>
                {feed.distro} {feed.release}
                {feed.platformStream ? ` (${feed.platformStream})` : ""} ·{" "}
                {feed.advisoryCount.toString()} advisory records
              </p>
              <p>Last successful check: {formatTimestamp(feed.checkedAt).local}</p>
              <p>
                Signed snapshot:{" "}
                {feed.snapshotAt ? formatTimestamp(feed.snapshotAt).local : "Not recorded"}
              </p>
              <p>Expires: {formatTimestamp(feed.expiresAt).local}</p>
              <p>Last attempt: {formatTimestamp(feed.attemptedAt).local}</p>
              {feed.error ? (
                <p role="alert" className="text-destructive">
                  Feed error: {feed.error}
                </p>
              ) : null}
              <p className="break-all">Source: {feed.sourceUrl}</p>
              <p className="break-all font-mono">
                Snapshot SHA-256: {feed.sourceSha256 || "Unavailable"}
              </p>
              {feed.artifacts.length > 0 ? (
                <details>
                  <summary className="cursor-pointer">Source artifact integrity</summary>
                  <ul className="mt-2 grid gap-3">
                    {feed.artifacts.map((artifact) => (
                      <li key={artifact.url} className="grid gap-1 break-all">
                        <p>{artifact.url}</p>
                        <p className="font-mono">
                          SHA-256:{" "}
                          {Array.from(artifact.sha256, (byte) =>
                            byte.toString(16).padStart(2, "0"),
                          ).join("")}
                        </p>
                        <p className="font-mono">
                          Signer: {artifact.signerFingerprint || "Signature not recorded"}
                        </p>
                      </li>
                    ))}
                  </ul>
                </details>
              ) : null}
            </article>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
