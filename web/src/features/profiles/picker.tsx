import { useState } from "react";
import { useQueries, useQuery } from "@tanstack/react-query";
import { SearchPicker, type PickerProps } from "@/components/ui/search-picker";
import { Button } from "@/components/ui/button";
import { RpcError } from "@/components/ui/rpc-error";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { toRpcFailure } from "@/lib/errors";
import { formatRevisionNumber } from "./model";
import {
  profilesQueryOptions,
  profileRevisionQueryOptions,
  profileRevisionsQueryOptions,
} from "./queries";

export function ProfilePicker({
  onRevisionChange,
  ...props
}: PickerProps & { onRevisionChange?: (revisionId: string) => void }) {
  const lifetime = useAuthLifetime();
  const [pageToken, setPageToken] = useState("");
  const query = useQuery(profilesQueryOptions(lifetime, 100, pageToken));
  const selected = useQuery({
    ...profileRevisionQueryOptions(lifetime, props.value, ""),
    enabled: !!props.value,
  });
  const options = (query.data?.profiles ?? []).map((profile) => ({
    value: profile.profileId,
    label: profile.name,
    description: `Latest version ${profile.revisionNumber}`,
  }));
  if (selected.data && !options.some((option) => option.value === props.value))
    options.unshift({
      value: props.value,
      label: selected.data.spec?.name || "Unnamed profile",
      description: `Latest version ${selected.data.revisionNumber}`,
    });
  return (
    <SearchPicker
      {...props}
      onChange={(next) => {
        props.onChange(next);
        onRevisionChange?.(
          query.data?.profiles.find((profile) => profile.profileId === next)?.revisionId ?? "",
        );
      }}
      options={options}
      note="Search within this page of up to 100 profiles."
    >
      {query.isPending ? <p role="status">Loading profiles…</p> : null}
      {query.error ? <RpcError failure={toRpcFailure(query.error)} /> : null}
      {selected.error ? <RpcError failure={toRpcFailure(selected.error)} /> : null}
      <div className="flex gap-2">
        {pageToken ? (
          <Button
            type="button"
            variant="outline"
            disabled={props.disabled || query.isFetching}
            onClick={() => setPageToken("")}
          >
            First profiles
          </Button>
        ) : null}
        {query.data?.nextPageToken ? (
          <Button
            type="button"
            variant="outline"
            disabled={props.disabled || query.isFetching}
            onClick={() => setPageToken(query.data?.nextPageToken ?? "")}
          >
            More profiles
          </Button>
        ) : null}
      </div>
    </SearchPicker>
  );
}

export function ProfileRevisionPicker({
  profileId: fixedProfile,
  ...props
}: PickerProps & { profileId?: string }) {
  const lifetime = useAuthLifetime();
  const [chosenProfile, setChosenProfile] = useState("");
  const [cursor, setCursor] = useState({ profile: "", token: "" });
  const profiles = useQuery(profilesQueryOptions(lifetime, 100, ""));
  const profileId =
    fixedProfile ||
    chosenProfile ||
    profiles.data?.profiles.find((profile) => profile.revisionId === props.value)?.profileId ||
    "";
  const query = useQuery(
    profileRevisionsQueryOptions(
      lifetime,
      profileId,
      cursor.profile === profileId ? cursor.token : "",
    ),
  );
  const exact = useQuery({
    ...profileRevisionQueryOptions(lifetime, profileId, props.value),
    enabled: !!profileId && !!props.value,
  });
  const options = (query.data?.revisions ?? []).map((revision) => ({
    value: revision.revisionId,
    label: `${revision.name || "Unnamed profile"}, version ${revision.revisionNumber}`,
  }));
  if (exact.data && !options.some((option) => option.value === props.value))
    options.unshift({
      value: props.value,
      label: `${exact.data.spec?.name || "Unnamed profile"}, version ${exact.data.revisionNumber}`,
    });
  return (
    <div className="grid gap-2">
      {!fixedProfile ? (
        <ProfilePicker
          label="Profile"
          value={profileId}
          disabled={props.disabled}
          onChange={setChosenProfile}
          onRevisionChange={props.onChange}
        />
      ) : null}
      <SearchPicker
        {...props}
        disabled={props.disabled || !profileId}
        options={options}
        note="Search within this page of up to 100 saved versions."
      >
        {profileId && query.isPending ? <p role="status">Loading versions…</p> : null}
        {query.error ? <RpcError failure={toRpcFailure(query.error)} /> : null}
        {exact.error ? <RpcError failure={toRpcFailure(exact.error)} /> : null}
        <div className="flex gap-2">
          {cursor.token ? (
            <Button
              type="button"
              variant="outline"
              disabled={props.disabled || query.isFetching}
              onClick={() => setCursor({ profile: profileId, token: "" })}
            >
              Latest versions
            </Button>
          ) : null}
          {query.data?.nextPageToken ? (
            <Button
              type="button"
              variant="outline"
              disabled={props.disabled || query.isFetching}
              onClick={() =>
                setCursor({ profile: profileId, token: query.data?.nextPageToken ?? "" })
              }
            >
              Older versions
            </Button>
          ) : null}
        </div>
      </SearchPicker>
    </div>
  );
}

// Names a saved profile version for read-only lists. An assignment carries
// only the version identity, so older versions are found in the version
// history of the first page of profiles, fetched only when no latest matches.
export function ProfileVersionName({ value }: { value: string }) {
  const lifetime = useAuthLifetime();
  const heads = useQuery(profilesQueryOptions(lifetime, 100, ""));
  const latest = heads.data?.profiles.find((profile) => profile.revisionId === value);
  const histories = useQueries({
    queries:
      latest || !heads.data
        ? []
        : heads.data.profiles.map((profile) =>
            profileRevisionsQueryOptions(lifetime, profile.profileId, ""),
          ),
  });
  const older = histories
    .flatMap((history) => history.data?.revisions ?? [])
    .find((revision) => revision.revisionId === value);
  const match = latest ?? older;
  if (match)
    return (
      <>
        {match.name || "Unnamed profile"}, version {formatRevisionNumber(match.revisionNumber)}
        {latest ? "" : " (a newer version exists)"}
      </>
    );
  if (heads.isPending || histories.some((history) => history.isPending))
    return <>Loading profile name…</>;
  if (heads.error || histories.some((history) => history.error))
    return <>Profile name unavailable</>;
  return <>Profile version not found on the first page of profiles</>;
}
