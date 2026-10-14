// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import { useBreadcrumbTitle } from "@/components/layout/breadcrumb-title";
import { useAuthLifetime } from "@/hooks/use-auth-lifetime";
import { profileRevisionQueryOptions } from "./queries";

// Names the profile in the console breadcrumb from the latest version the page already reads.
export function useProfileBreadcrumbTitle(profileId: string) {
  const lifetime = useAuthLifetime();
  const head = useQuery({
    ...profileRevisionQueryOptions(lifetime, profileId, ""),
    select: (revision) => revision.spec?.name.trim() || "Unnamed profile",
  });
  useBreadcrumbTitle(head.data);
}
