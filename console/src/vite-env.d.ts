/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Where shoc is, when the console is not served from the same origin. */
  readonly VITE_SHOC_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
