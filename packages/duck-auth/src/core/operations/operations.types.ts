export namespace Operations {
  export interface State {
    /** When true, every mounted route returns 503 except session/healthz. */
    maintenance: { on: boolean; message?: string; retryAfterSec?: number; since?: number }
    /** When true, reads succeed but every mutating route returns 423. */
    readOnly: { on: boolean; since?: number }
  }
}
