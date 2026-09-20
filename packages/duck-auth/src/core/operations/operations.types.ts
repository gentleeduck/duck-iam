/** Maintenance and read-only state, the per-route exemptions, and the store that persists them. */
export namespace Operations {
  /** What an operator set, and when. A window that ended is kept so it can still be read back. */
  export interface State {
    /** When true, every mounted route returns 503 except one exempted from maintenance. */
    maintenance: { on: boolean; message?: string; retryAfterSec?: number; since?: number }
    /** When true, reads succeed but every mutating route returns 423. */
    readOnly: { on: boolean; since?: number }
    /** The last maintenance window, kept after it ends rather than dropped with the live one. */
    lastMaintenance?: { since: number; endedAt: number; message?: string; retryAfterSec?: number }
  }

  /** Named per mode, because one flag covering both meant a route exempted so it could answer during
   *  maintenance also kept accepting writes through a read-only freeze. */
  export interface Exempt {
    maintenance?: boolean
    readOnly?: boolean
  }

  /** What a route says about itself, for the case the HTTP method does not settle. */
  export interface Route extends Exempt {
    /** Magic-link redemption and an OAuth callback are GETs that consume a one-time credential and open a
     *  session, so the method alone let them through a freeze. */
    mutates?: boolean
  }

  /** Somewhere to keep the switches, so a node that restarts mid-window comes back inside it. */
  export interface Store {
    /** The persisted switches. Rejects `AUTH_OPERATION_NOT_FOUND` where nothing has been saved yet, which
     *  `hydrate()` reads back as "keep the defaults"; a store that is down rejects its own code and takes
     *  the boot down with it, rather than quietly serving traffic through a freeze window. */
    load(): Promise<State>
    save(state: State): Promise<void>
  }
}
