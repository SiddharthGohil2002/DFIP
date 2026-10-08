/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** 'desktop' when built with --mode desktop (see .env.desktop); unset for the web portal. */
  readonly VITE_TARGET?: string;
  /** Optional absolute origin of the API for the web build (defaults to same origin). */
  readonly VITE_API_ORIGIN?: string;
  readonly VITE_APP_VERSION?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
