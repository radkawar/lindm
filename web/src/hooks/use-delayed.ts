// SPDX-License-Identifier: Apache-2.0

import { useEffect, useState } from "react";

// Typing pause before a picker asks the server for its search.
export const SEARCH_DELAY_MS = 250;

// The value once it has stopped changing for delay milliseconds.
export function useDelayed<T>(value: T, delay: number): T {
  const [delayed, setDelayed] = useState(value);
  useEffect(() => {
    const timer = window.setTimeout(() => setDelayed(value), delay);
    return () => window.clearTimeout(timer);
  }, [value, delay]);
  return delayed;
}
