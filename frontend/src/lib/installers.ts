import { useEffect, useState } from 'react';
import { api, serverUrl } from './api';

export interface Installer {
  filename: string;
  size: number;
  sha256: string;
  format: string;
  url: string;
  published_at?: string;
}

let cache: Promise<Installer[]> | null = null;

/** Desktop installers published on the server (storage/downloads); [] when none. Fetched once per page load. */
export function useInstallers(): Installer[] | null {
  const [files, setFiles] = useState<Installer[] | null>(null);
  useEffect(() => {
    cache ??= api<{ files: Installer[] }>('/desktop/download/info')
      .then((r) => r.files || [])
      .catch(() => []);
    let alive = true;
    cache.then((f) => alive && setFiles(f));
    return () => {
      alive = false;
    };
  }, []);
  return files;
}

/** The installer to offer first: the NSIS setup .exe if published, else the first file. */
export function primaryInstaller(files: Installer[] | null): Installer | null {
  if (!files?.length) return null;
  return files.find((f) => f.format === 'EXE') || files[0];
}

export const installerHref = (f: Installer) => serverUrl() + f.url;

/** "2.1.0" from "DFIP-Investigator_2.1.0_x64-setup.exe". */
export const installerVersion = (f: Installer) => f.filename.match(/_(\d+\.\d+\.\d+)_/)?.[1] || '';
