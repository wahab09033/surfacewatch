"use client";

/** Data-fetching hooks. Small on purpose — no client-cache library. */

import { useCallback, useEffect, useRef, useState } from "react";

import { ApiError } from "./api";

export interface QueryState<T> {
  data: T | null;
  error: ApiError | null;
  /** True only on the first load, so refreshes do not flash skeletons. */
  loading: boolean;
  /** True while a background refetch is in flight. */
  refreshing: boolean;
  reload: () => void;
}

/**
 * Run an async fetch and track its state.
 *
 * `deps` behaves like a useEffect dep array. The fetcher receives an
 * AbortSignal — pass it to the API call so a superseded request (filter typed
 * quickly, page unmounted) cannot land after a newer one and overwrite it.
 */
export function useQuery<T>(
  fetcher: (signal: AbortSignal) => Promise<T>,
  deps: unknown[],
): QueryState<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [nonce, setNonce] = useState(0);

  // Held in a ref so changing the fetcher identity every render (inline arrow
  // functions, which is how every caller writes it) does not re-trigger.
  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;

  const loadedOnce = useRef(false);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;

    if (loadedOnce.current) setRefreshing(true);

    fetcherRef
      .current(controller.signal)
      .then((result) => {
        if (!active) return;
        setData(result);
        setError(null);
      })
      .catch((err: unknown) => {
        if (!active) return;
        // An abort is expected teardown, not a failure to surface.
        if (err instanceof DOMException && err.name === "AbortError") return;
        setError(err instanceof ApiError ? err : new ApiError(0, "Something went wrong."));
      })
      .finally(() => {
        if (!active) return;
        loadedOnce.current = true;
        setLoading(false);
        setRefreshing(false);
      });

    return () => {
      active = false;
      controller.abort();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce]);

  const reload = useCallback(() => setNonce((n) => n + 1), []);

  return { data, error, loading, refreshing, reload };
}

/**
 * Re-run `callback` on an interval, but only while the tab is visible.
 *
 * Polling a backgrounded tab burns the user's battery and our rate limit for
 * data nobody is looking at. Also fires immediately on becoming visible again,
 * so returning to the tab shows current data rather than whatever was on screen
 * when it was hidden.
 */
export function usePoll(callback: () => void, intervalMs: number | null): void {
  const saved = useRef(callback);
  saved.current = callback;

  useEffect(() => {
    if (intervalMs === null) return;

    let timer: ReturnType<typeof setInterval> | null = null;

    const start = () => {
      if (timer !== null) return;
      timer = setInterval(() => saved.current(), intervalMs);
    };
    const stop = () => {
      if (timer === null) return;
      clearInterval(timer);
      timer = null;
    };

    const onVisibility = () => {
      if (document.visibilityState === "visible") {
        saved.current();
        start();
      } else {
        stop();
      }
    };

    if (document.visibilityState === "visible") start();
    document.addEventListener("visibilitychange", onVisibility);

    return () => {
      stop();
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [intervalMs]);
}

/** Delay a rapidly-changing value — search inputs, mostly. */
export function useDebounced<T>(value: T, delayMs = 300): T {
  const [debounced, setDebounced] = useState(value);

  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delayMs);
    return () => clearTimeout(timer);
  }, [value, delayMs]);

  return debounced;
}

/** Read/write a piece of state that survives reloads. */
export function useLocalStorage<T>(
  key: string,
  initial: T,
): [T, (value: T | ((previous: T) => T)) => void] {
  // Always start from `initial` so the server render and the first client
  // render agree; the stored value is applied in an effect below. Reading
  // localStorage during render would hydrate-mismatch.
  const [value, setValue] = useState<T>(initial);

  useEffect(() => {
    try {
      const stored = window.localStorage.getItem(key);
      if (stored !== null) setValue(JSON.parse(stored) as T);
    } catch {
      // Corrupt entry or storage disabled (private mode, blocked cookies) —
      // the in-memory default is a fine fallback.
    }
  }, [key]);

  const update = useCallback(
    (next: T | ((previous: T) => T)) => {
      setValue((previous) => {
        const resolved =
          typeof next === "function" ? (next as (p: T) => T)(previous) : next;
        try {
          window.localStorage.setItem(key, JSON.stringify(resolved));
        } catch {
          // Quota or disabled storage: keep the value in memory for this session.
        }
        return resolved;
      });
    },
    [key],
  );

  return [value, update];
}

/** True once the component has mounted on the client. */
export function useMounted(): boolean {
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  return mounted;
}
