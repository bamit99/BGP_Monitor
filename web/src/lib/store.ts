import { create } from "zustand";

export interface FilterState {
  severities: Record<string, boolean>;
  kinds: Record<string, boolean>;
  ownedOnly: boolean;
  query: string;
  toggleSeverity: (severity: string) => void;
  toggleKind: (kind: string) => void;
  setOwnedOnly: (value: boolean) => void;
  setQuery: (value: string) => void;
  reset: () => void;
}

const initialSeverities: Record<string, boolean> = {
  CRITICAL: true,
  HIGH: true,
  MEDIUM: true,
  LOW: false,
  INFO: false,
};

export const useFilters = create<FilterState>((set) => ({
  severities: { ...initialSeverities },
  kinds: {},
  ownedOnly: false,
  query: "",
  toggleSeverity: (severity) =>
    set((s) => ({ severities: { ...s.severities, [severity]: !s.severities[severity] } })),
  toggleKind: (kind) => set((s) => ({ kinds: { ...s.kinds, [kind]: !s.kinds[kind] } })),
  setOwnedOnly: (ownedOnly) => set({ ownedOnly }),
  setQuery: (query) => set({ query }),
  reset: () => set({ severities: { ...initialSeverities }, kinds: {}, ownedOnly: false, query: "" }),
}));
