import type { Events } from '~/core/events/events.types'
import { AuthError } from '../errors'
import type { Operations } from './operations.types'

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
 */

const MESSAGE_MAX_LENGTH = 512
const RETRY_AFTER_MAX_SEC = 86_400
const RETRY_AFTER_DEFAULT_SEC = 60

/** The methods that cannot write. Everything else does, including whatever HTTP adds next. */
const SAFE_METHODS: ReadonlySet<string> = new Set(['GET', 'HEAD', 'OPTIONS', 'TRACE'])

/** `Retry-After` is a non-negative whole number of seconds, so anything else cannot be acted on: a
 *  negative one is meaningless and a NaN serialises to null. */
function clampRetryAfter(seconds: number): number {
  if (!Number.isFinite(seconds)) return RETRY_AFTER_DEFAULT_SEC
  return Math.min(Math.max(0, Math.floor(seconds)), RETRY_AFTER_MAX_SEC)
}

/** An operator-authored string that an adapter may put in a header rather than a body, so CR and LF
 *  come out before it can carry a second header with it. */
function clampMessage(message: string): string {
  // biome-ignore lint/suspicious/noControlCharactersInRegex: stripping them is the point.
  return message.replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, MESSAGE_MAX_LENGTH)
}

export class OperationsImpl {
  private _state: Operations.State = {
    maintenance: { on: false },
    readOnly: { on: false },
  }

  constructor(
    private readonly _events: Events.IBus,
    private readonly _store?: Operations.Store,
  ) {}

  /**
   * Adopt the persisted switches, if a store was wired.
   *
   * Nothing is persisted without one, so a node that restarted during a maintenance window came
   * back serving traffic, and a rolling deploy is exactly when the window is on.
   */
  async hydrate(): Promise<Operations.State> {
    const stored = await this._store?.load()
    if (stored) this._state = stored
    return this.snapshot()
  }

  /** Read the current state snapshot. */
  snapshot(): Operations.State {
    return {
      maintenance: { ...this._state.maintenance },
      readOnly: { ...this._state.readOnly },
      ...(this._state.lastMaintenance && { lastMaintenance: { ...this._state.lastMaintenance } }),
    }
  }

  /**
   * Toggle maintenance mode. Emits `maintenance.on` / `maintenance.off`
   * so multi-instance fleets can subscribe and propagate.
   *
   * A call that changes nothing emits nothing: the natural way to consume `maintenance.on` is to
   * call this on the local instance, and an unconditional emit made that a broadcast storm.
   */
  async maintenance(on: boolean, opts: { message?: string; retryAfterSec?: number } = {}): Promise<Operations.State> {
    if (on) {
      await this._maintenanceOn(opts)
    } else {
      await this._maintenanceOff()
    }
    // The resulting state, so a caller does not have to follow every toggle
    // with `snapshot()` to see what it actually set.
    return this.snapshot()
  }

  /** Toggle read-only mode. Same shape as maintenance, and propagated the same way. */
  async readOnly(on: boolean): Promise<Operations.State> {
    if (this._state.readOnly.on === on) return this.snapshot()
    this._state.readOnly = on ? { on: true, since: Date.now() } : { on: false }
    await this._persist()
    // Maintenance propagated and this did not, so an operator who froze writes on one node of a
    // fleet had frozen one node.
    await this._events.emit(on ? 'readonly.on' : 'readonly.off', {})
    return this.snapshot()
  }

  /**
   * Predicate run by every server adapter before dispatch. Throws the
   * appropriate AuthError so the adapter's handleError path
   * surfaces the right status + retry hint.
   */
  assertOperationsForRoute(method: string, route: Operations.Route = {}): void {
    if (this._state.maintenance.on && !route.maintenance) {
      const meta: { retryAfter: number; message?: string } = {
        retryAfter: this._state.maintenance.retryAfterSec ?? RETRY_AFTER_DEFAULT_SEC,
      }
      if (this._state.maintenance.message !== undefined) meta.message = this._state.maintenance.message
      throw new AuthError('AUTH_MAINTENANCE', meta)
    }
    if (this._state.readOnly.on && !route.readOnly && (route.mutates ?? isMutatingMethod(method))) {
      throw new AuthError('AUTH_READONLY_MODE')
    }
  }

  private async _maintenanceOn(opts: { message?: string; retryAfterSec?: number }): Promise<void> {
    // Normalised here rather than at the throw, so the stored state, the emitted event and the
    // error meta cannot disagree about what the operator asked for. Clamped rather than refused:
    // maintenance going on is the part that matters during an incident, and a bad retry hint is
    // advisory - failing the call would leave the fleet serving traffic over a typo.
    const current = this._state.maintenance
    const message = opts.message === undefined ? (current.on ? current.message : undefined) : clampMessage(opts.message)
    const retryAfterSec =
      opts.retryAfterSec === undefined
        ? current.on
          ? current.retryAfterSec
          : undefined
        : clampRetryAfter(opts.retryAfterSec)
    if (current.on && current.message === message && current.retryAfterSec === retryAfterSec) return
    this._state.maintenance = {
      on: true,
      // Kept across a re-assert, or two nodes reporting one window disagree about when it began.
      since: current.on ? (current.since ?? Date.now()) : Date.now(),
      ...(message !== undefined && { message }),
      ...(retryAfterSec !== undefined && { retryAfterSec }),
    }
    await this._persist()
    const payload: { message?: string; retryAfter?: number } = {}
    if (message !== undefined) payload.message = message
    if (retryAfterSec !== undefined) payload.retryAfter = retryAfterSec
    await this._events.emit('maintenance.on', payload)
  }

  private async _maintenanceOff(): Promise<void> {
    const ended = this._state.maintenance
    if (!ended.on) return
    this._state.lastMaintenance = {
      endedAt: Date.now(),
      since: ended.since ?? Date.now(),
      ...(ended.message !== undefined && { message: ended.message }),
      ...(ended.retryAfterSec !== undefined && { retryAfterSec: ended.retryAfterSec }),
    }
    this._state.maintenance = { on: false }
    await this._persist()
    await this._events.emit('maintenance.off', {})
  }

  private async _persist(): Promise<void> {
    await this._store?.save(this.snapshot())
  }
}

/** Anything not known to be safe writes, so a method this predates is refused rather than passed. */
function isMutatingMethod(method: string): boolean {
  if (typeof method !== 'string') return true
  return !SAFE_METHODS.has(method.toUpperCase())
}

/** Factory for {@link OperationsImpl}. */
export function operations(events: Events.IBus, store?: Operations.Store): OperationsImpl {
  return new OperationsImpl(events, store)
}
