/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { AuthErrorObject } from '../errors'
import type { Events } from '../types/events'

/**
 * Per-tenant operational mode snapshot. Persisted in-process for the
 * memory tier; multi-instance fleets should swap in a Redis-backed
 * store that emits maintenance.on / maintenance.off via pub/sub so
 * every node converges within seconds of the toggle.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface OperationsState {
  /** When true, every mounted route returns 503 except session/healthz. */
  maintenance: { on: boolean; message?: string; retryAfterSec?: number; since?: number }
  /** When true, reads succeed but every mutating route returns 423. */
  readOnly: { on: boolean; since?: number }
}

/**
 * Operations facet. Drives the two ambient deploy switches every
 * production deployment hits within the first month:
 *
 * - `auth.operations.maintenance(true)` blocks new auth (sign-in /
 *   sign-up / refresh) while existing sessions continue to resolve.
 *   Server adapters consult `assertOperationsForRoute()` and surface
 *   AUTH/MAINTENANCE with Retry-After.
 *
 * - `auth.operations.readOnly(true)` accepts reads + session resolve
 *   but every mutating route raises AUTH/READONLY_MODE. Migration
 *   cutovers, DR drills, freeze windows.
 *
 * DESIGN section O1 + O2.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export class OperationsFacet {
  private _state: OperationsState = {
    maintenance: { on: false },
    readOnly: { on: false },
  }

  constructor(private readonly _events: Events.IBus) {}

  /** Read the current state snapshot. */
  snapshot(): OperationsState {
    return {
      maintenance: { ...this._state.maintenance },
      readOnly: { ...this._state.readOnly },
    }
  }

  /**
   * Toggle maintenance mode. Emits `maintenance.on` / `maintenance.off`
   * so multi-instance fleets can subscribe and propagate.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async maintenance(on: boolean, opts: { message?: string; retryAfterSec?: number } = {}): Promise<void> {
    if (on) {
      this._state.maintenance = {
        on: true,
        since: Date.now(),
        ...(opts.message !== undefined && { message: opts.message }),
        ...(opts.retryAfterSec !== undefined && { retryAfterSec: opts.retryAfterSec }),
      }
      const payload: { message?: string; retryAfter?: number } = {}
      if (opts.message !== undefined) payload.message = opts.message
      if (opts.retryAfterSec !== undefined) payload.retryAfter = opts.retryAfterSec
      await this._events.emit('maintenance.on', payload)
    } else {
      this._state.maintenance = { on: false }
      await this._events.emit('maintenance.off', {})
    }
  }

  /** Toggle read-only mode. Same shape as maintenance, no event yet. */
  async readOnly(on: boolean): Promise<void> {
    this._state.readOnly = on ? { on: true, since: Date.now() } : { on: false }
  }

  /**
   * Predicate run by every server adapter before dispatch. Throws the
   * appropriate AuthErrorObject so the adapter's handleError path
   * surfaces the right status + retry hint.
   *
   * @param method HTTP method (POST/GET/...)
   * @param exempt routes that should pass through unaffected (e.g. /healthz, /session)
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  assertOperationsForRoute(method: string, exempt: { healthz?: boolean; session?: boolean } = {}): void {
    if (exempt.healthz || exempt.session) return
    if (this._state.maintenance.on) {
      const meta: { retryAfter: number; message?: string } = {
        retryAfter: this._state.maintenance.retryAfterSec ?? 60,
      }
      if (this._state.maintenance.message !== undefined) meta.message = this._state.maintenance.message
      throw new AuthErrorObject('AUTH/MAINTENANCE', meta)
    }
    if (this._state.readOnly.on && isMutatingMethod(method)) {
      throw new AuthErrorObject('AUTH/READONLY_MODE')
    }
  }
}

/** HTTP methods that mutate state and are blocked in read-only mode. */
function isMutatingMethod(method: string): boolean {
  const m = method.toUpperCase()
  return m === 'POST' || m === 'PUT' || m === 'PATCH' || m === 'DELETE'
}

/**
 * Namespace merge for OperationsFacet. Co-locates the config + input + output
 * shapes alongside the class via TS class+namespace merging. Consumers can
 * write either the flat name (e.g. OperationsState) or the
 * namespaced form (OperationsFacet.IState); both
 * resolve to the same type.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace OperationsFacet {
  /** Alias for the flat `OperationsState` type. */
  export type IState = OperationsState
}
