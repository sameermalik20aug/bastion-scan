/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Base URL of the Bastion backend (e.g. http://localhost:8000). */
  readonly VITE_API_BASE_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
