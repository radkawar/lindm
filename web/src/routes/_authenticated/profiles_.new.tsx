import { createFileRoute, Link } from "@tanstack/react-router";
import { useState } from "react";
import { ProfileEditor } from "@/features/profiles/editor";
import {
  replaceReservedCreateProfileId,
  reservedCreateProfileId,
} from "@/features/profiles/attempt";
import { CATALOG_SEMANTICS } from "@/features/profiles/model";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";

export const Route = createFileRoute("/_authenticated/profiles_/new")({
  component: ProfileCreateRoute,
});

function ProfileCreateRoute() {
  const lifetime = useAuthLifetime();
  const [profileId, setProfileId] = useState(() => reservedCreateProfileId(lifetime));
  return (
    <section className="flex min-w-0 flex-col gap-4">
      <Link
        to="/profiles"
        search={{ pageSize: 50, pageToken: "" }}
        className="w-fit text-sm underline underline-offset-4"
      >
        Back to service profiles
      </Link>
      <div>
        <h1 className="text-2xl font-semibold">Publish a service profile</h1>
        <p className="max-w-3xl text-sm text-muted-foreground">
          Creation reserves profile ID {profileId}. {CATALOG_SEMANTICS}
        </p>
      </div>
      <ProfileEditor
        key={profileId}
        mode="create"
        profileId={profileId}
        sourceNote="The first publish omits expected revision. It creates this profile only if the reserved profile ID is not already in the catalog."
        onPrepareAnother={() => setProfileId(replaceReservedCreateProfileId(lifetime))}
      />
    </section>
  );
}
