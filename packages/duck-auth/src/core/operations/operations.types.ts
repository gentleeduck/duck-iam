export namespace Operations {
  /** What an operator set, and when. A window that ended is kept so it can still be read back. */
  export interface State {
    /** When true, every mounted route returns 503 except one exempted from maintenance. */
    maintenance: { on: boolean; message?: string; retryAfterSec?: number; since?: number }
    /** When true, reads succeed but every mutating route returns 423. */
    readOnly: { on: boolean; since?: number }
    /** The last maintenance window, after it ended. Turning maintenance off used to drop both. */
    lastMaintenance?: { since: number; endedAt: number; message?: string; retryAfterSec?: number }
  }

  /**
   * What a route is exempt from, named per mode.
   *
   * The flags used to be `healthz` and `session`, and either one skipped both modes: a route
   * marked exempt so it could answer during maintenance, which is the point, was also the route
   * that kept accepting writes during a read-only freeze.
   */
  export interface Exempt {
    maintenance?: boolean
    readOnly?: boolean
  }

  /** What a route says about itself, for the case the HTTP method does not settle. */
  export interface Route extends Exempt {
    /**
     * Whether this route writes. Magic-link redemption and an OAuth callback are GETs that consume
     * a one-time credential and open a session, so the method alone let them through a freeze.
     */
    mutates?: boolean
  }

  /** Somewhere to keep the switches, so a node that restarts mid-window comes back inside it. */
  export interface Store {
    load(): Promise<State | null>
    save(state: State): Promise<void>
  }
}
