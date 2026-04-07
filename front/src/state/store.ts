import { type SystemInfo, type TrafficSnapshot, type Interface } from '@schemas';

type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends Record<string, unknown> ? DeepPartial<T[P]> : T[P];
};

/**
 * Global application state
 */
export interface AppState {
  // System
  systemInfo: SystemInfo | null;
  traffic: TrafficSnapshot | null;

  // Network
  interfaces: Interface[];

  // Auth
  isAuthenticated: boolean;
  tokenExpiresAt: number | null;

  // UI
  currentPage: string;
  isLoading: boolean;
  error: string | null;
}

const initialState: AppState = {
  systemInfo: null,
  traffic: null,
  interfaces: [],
  isAuthenticated: false,
  tokenExpiresAt: null,
  currentPage: 'dashboard',
  isLoading: false,
  error: null,
};

// Create state store
class Store {
  private state: AppState;
  private listeners: Set<(state: AppState, prevState: AppState) => void>;

  constructor() {
    this.state = { ...initialState };
    this.listeners = new Set();
  }

  /**
   * Get current state (use sparingly, prefer subscribe)
   */
  getState(): Readonly<AppState> {
    return this.state;
  }

  /**
   * Update state with partial changes
   */
  setState(updates: DeepPartial<AppState>): void {
    const prevState = { ...this.state };
    this.state = { ...this.state, ...updates } as AppState;
    this.notify(prevState);
  }

  /**
   * Subscribe to state changes
   * Returns unsubscribe function
   */
  subscribe(callback: (state: AppState, prevState: AppState) => void): () => void {
    this.listeners.add(callback);
    return () => this.listeners.delete(callback);
  }

  /**
   * Notify all listeners
   */
  private notify(prevState: AppState): void {
    this.listeners.forEach(callback => {
      try {
        callback(this.state, prevState);
      } catch (error) {
        console.error('Store listener error:', error);
      }
    });
  }
}

// Singleton store instance
export const store = new Store();
