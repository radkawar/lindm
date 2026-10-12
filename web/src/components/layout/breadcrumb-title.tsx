import { createContext, useContext, useEffect } from "react";

// Detail pages name their record (hostname, profile or secret name) in the shell
// breadcrumb instead of a generic "details" label. The shell falls back to the
// generic label while the record loads or when it has no name.
export const BreadcrumbTitleContext = createContext<(title: string | null) => void>(() => {});

export function useBreadcrumbTitle(title: string | undefined) {
  const setTitle = useContext(BreadcrumbTitleContext);
  useEffect(() => {
    if (!title) return;
    setTitle(title);
    return () => setTitle(null);
  }, [setTitle, title]);
}
