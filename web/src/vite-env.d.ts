/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Bearer token for the API and WebSocket. Build-time; inlined by Vite. */
  readonly VITE_API_TOKEN?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}