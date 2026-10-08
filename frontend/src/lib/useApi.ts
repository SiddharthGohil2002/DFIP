import { useCallback, useEffect, useRef, useState } from 'react';
import { api } from './api';

export interface ApiState<T> {
  data: T | null;
  error: string;
  loading: boolean;
  reload: () => void;
}

/**
 * Loads `path` (skipped when null) and reloads whenever it changes.
 * Responses that arrive after a newer request started are ignored.
 */
export function useApi<T = any>(path: string | null, options: { pollMs?: number } = {}): ApiState<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(path !== null);
  const seq = useRef(0);

  const load = useCallback(
    (quiet = false) => {
      if (path === null) {
        setData(null);
        setLoading(false);
        return;
      }
      const id = ++seq.current;
      if (!quiet) setLoading(true);
      api<T>(path)
        .then((d) => {
          if (id !== seq.current) return;
          setData(d);
          setError('');
        })
        .catch((e) => id === seq.current && setError(e.message))
        .finally(() => id === seq.current && setLoading(false));
    },
    [path],
  );

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (!options.pollMs || path === null) return;
    const t = setInterval(() => load(true), options.pollMs);
    return () => clearInterval(t);
  }, [options.pollMs, load, path]);

  return { data, error, loading, reload: () => load(true) };
}
