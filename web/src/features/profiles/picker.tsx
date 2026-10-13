import { useState } from "react";
import { keepPreviousData, useQueries, useQuery } from "@tanstack/react-query";
import { SearchPicker, type PickerProps } from "@/components/ui/search-picker";
import { Button } from "@/components/ui/button";
import { RpcError } from "@/components/ui/rpc-error";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { SEARCH_DELAY_MS, useDelayed } from "@/hooks/use-delayed";
import { toRpcFailure } from "@/lib/errors";
import { formatRevisionNumber } from "./model";
import {
  profilesQueryOptions,
  profileRevisionQueryOptions,
  profileRevisionsQueryOptions,
} from "./queries";

export type ProfileChoice = { profileId: string; revisionId: string; label: string };

// Chooses a profile by name; onChoose receives its latest published version.
export function ProfilePicker({
  onChoose,
  ...props
}: PickerProps & { onChoose?: (choice: ProfileChoice | null) => void }) {
  const lifetime = useAuthLifetime();
  const [search, setSearch] = useState("");
  // The server searches every profile by name; typing waits briefly before asking.
  const term = search.trim().slice(0, 200);
  const nameSearch = useDelayed(term, SEARCH_DELAY_MS);
  // Until the server answers for the typed text, loaded profiles that already
  // match it stay choosable (typing then pressing Enter picks one at once).
  const settling = term !== nameSearch;
  // Paging restarts whenever the search changes: a token belongs to its search.
  const [cursor, setCursor] = useState({ search: "", token: "" });
  const pageToken = cursor.search === nameSearch ? cursor.token : "";
  const query = useQuery({
    ...profilesQueryOptions(lifetime, 100, pageToken, nameSearch),
    placeholderData: keepPreviousData,
  });
  const provisional = settling || query.isPlaceholderData;
  const selected = useQuery({
    ...profileRevisionQueryOptions(lifetime, props.value, ""),
    enabled: !!props.value,
  });
  const options = (query.data?.profiles ?? [])
    .filter((profile) => !provisional || profile.name.toLowerCase().includes(term.toLowerCase()))
    .map((profile) => ({
      value: profile.profileId,
      label: profile.name,
      description: `Latest version ${profile.revisionNumber}`,
    }));
  if (selected.data && !term && !options.some((option) => option.value === props.value))
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
        const profile = query.data?.profiles.find((entry) => entry.profileId === next);
        onChoose?.(
          profile
            ? {
                profileId: profile.profileId,
                revisionId: profile.revisionId,
                label: `${profile.name || "Unnamed profile"}, version ${profile.revisionNumber}`,
              }
            : null,
        );
      }}
      options={options}
      search={search}
      onSearchChange={setSearch}
      note={
        query.data?.nextPageToken && !provisional
          ? `Showing the first ${query.data.profiles.length} ${nameSearch ? "matches" : "profiles"}. Use More profiles for the rest.`
          : undefined
      }
      footer={
        provisional || query.isPending || query.error || pageToken || query.data?.nextPageToken ? (
          <>
            {provisional || query.isPending ? <p role="status">Loading profiles…</p> : null}
            {query.error ? <RpcError failure={toRpcFailure(query.error)} /> : null}
            <div className="flex gap-2">
              {pageToken ? (
                <Button
                  type="button"
                  variant="outline"
                  disabled={props.disabled || query.isFetching}
                  onClick={() => setCursor({ search: nameSearch, token: "" })}
                >
                  First profiles
                </Button>
              ) : null}
              {query.data?.nextPageToken ? (
                <Button
                  type="button"
                  variant="outline"
                  disabled={props.disabled || query.isFetching}
                  onClick={() =>
                    setCursor({ search: nameSearch, token: query.data?.nextPageToken ?? "" })
                  }
                >
                  More profiles
                </Button>
              ) : null}
            </div>
          </>
        ) : undefined
      }
    >
      {selected.error ? <RpcError failure={toRpcFailure(selected.error)} /> : null}
      {query.data?.profiles.length === 0 && !pageToken && !nameSearch ? (
        <p className="text-sm text-muted-foreground">No profiles yet. Create one under Profiles.</p>
      ) : null}
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
          onChoose={(choice) => props.onChange(choice?.revisionId ?? "")}
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
// `text` is the full name ("Workstation baseline, version 2"); `short` is the
// compact form for generated titles ("Workstation baseline v2").
export function useProfileVersionLabel(value: string): {
  text: string;
  short: string;
  ready: boolean;
} {
  const lifetime = useAuthLifetime();
  const heads = useQuery({ ...profilesQueryOptions(lifetime, 100, ""), enabled: !!value });
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
  if (!value) return { text: "No profile version", short: "", ready: false };
  if (match) {
    const name = match.name || "Unnamed profile";
    const number = formatRevisionNumber(match.revisionNumber);
    return {
      text: `${name}, version ${number}${latest ? "" : " (a newer version exists)"}`,
      short: `${name} v${number}`,
      ready: true,
    };
  }
  if (heads.isPending || histories.some((history) => history.isPending))
    return { text: "Loading profile name…", short: "", ready: false };
  if (heads.error || histories.some((history) => history.error))
    return { text: "Profile name unavailable", short: "", ready: false };
  return {
    text: "Profile version not found on the first page of profiles",
    short: "",
    ready: false,
  };
}
