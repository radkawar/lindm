import { createFileRoute } from "@tanstack/react-router";
import { ProfileDetailView } from "@/features/profiles/detail";
import { useProfileBreadcrumbTitle } from "@/features/profiles/breadcrumb";
import { profileRevisionQueryOptions } from "@/features/profiles/queries";
import { parseProfileDetailSearch } from "@/features/profiles/search";
import { getAuthLifetime } from "@/lib/auth-lifetime";
import { usableUuid } from "@/features/profiles/model";
import { ProfilePickerProvider } from "@/features/profiles/field-pickers";
import { DevicePicker, DeviceBindingPicker } from "@/features/devices/picker";
import { AccountPicker } from "@/features/auth/picker";
import { SecretPicker, SecretReferencePicker } from "@/features/secrets/picker";

export const Route = createFileRoute("/_authenticated/profiles_/$profileId")({
  validateSearch: parseProfileDetailSearch,
  params: {
    parse: ({ profileId }) => {
      const canonical = usableUuid(profileId);
      if (canonical === null) throw new Error("The profile URL must contain a valid profile ID.");
      return { profileId: canonical };
    },
  },
  loaderDeps: ({ search }) => search,
  loader: ({ context, params, deps }) => {
    const lifetime = getAuthLifetime();
    if (!lifetime) return;
    const loads = [
      context.queryClient.prefetchQuery(
        profileRevisionQueryOptions(lifetime, params.profileId, deps.revision),
      ),
    ];
    if (deps.revision !== "") {
      loads.push(
        context.queryClient.prefetchQuery(
          profileRevisionQueryOptions(lifetime, params.profileId, ""),
        ),
      );
    }
    return Promise.all(loads);
  },
  component: ProfileDetailRoute,
});

function ProfileDetailRoute() {
  const { profileId } = Route.useParams();
  const search = Route.useSearch();
  const navigate = Route.useNavigate();
  useProfileBreadcrumbTitle(profileId);
  return (
    <ProfilePickerProvider
      pickers={{
        device: DevicePicker,
        deviceBinding: DeviceBindingPicker,
        account: AccountPicker,
        secret: SecretPicker,
        secretReference: SecretReferencePicker,
      }}
    >
      <ProfileDetailView
        key={profileId}
        profileId={profileId}
        revision={search.revision}
        onSearch={(next) => void navigate({ search: next })}
      />
    </ProfilePickerProvider>
  );
}
