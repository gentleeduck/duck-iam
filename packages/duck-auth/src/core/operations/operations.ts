import type { Events } from '~/core/events/events.types'
import { orNull } from '../answer'
import { AuthError } from '../errors'
import type { Operations } from './operations.types'

/**
 * The two ambient deploy switches. The host reaches them through `assertOperationsForRoute()` from its
 * own middleware; no adapter this package ships calls it.
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

/** Maintenance and read-only mode: the two ambient switches a host gates its own routes on. */
export class OperationsImpl {
  private _state: Operations.State = {
    maintenance: { on: false },
    readOnly: { on: false },
  }

  constructor(
    private readonly _events: Events.IBus,
    private readonly _store?: Operations.Store,
  ) {}

  /** Adopts the persisted switches, when a store was wired.
   *  WARN: without one nothing persists, so a node restarting mid-window comes back serving traffic, and a
   *  rolling deploy is exactly when the window is on. */
  async hydrate(): Promise<Operations.State> {
    const stored = this._store ? await orNull(this._store.load()) : null
    if (stored) this._state = stored
    return this.snapshot()
  }

  /** A copy of the current switch state, safe for the caller to keep. */
  snapshot(): Operations.State {
    return {
      maintenance: { ...this._state.maintenance },
      readOnly: { ...this._state.readOnly },
      ...(this._state.lastMaintenance && { lastMaintenance: { ...this._state.lastMaintenance } }),
    }
  }

  /** Emits `maintenance.on` or `.off` for a fleet to propagate. A call that changes nothing emits nothing,
   *  since the natural way to consume the event is to call this locally, which an unconditional emit would
   *  turn into a broadcast storm. */
  async maintenance(on: boolean, opts: { message?: string; retryAfterSec?: number } = {}): Promise<Operations.State> {
    if (on) {
      await this._maintenanceOn(opts)
    } else {
      await this._maintenanceOff()
    }
    // The resulting state, so a caller need not follow every toggle with `snapshot()`.
    return this.snapshot()
  }

  /** Same shape as maintenance, and propagated the same way. */
  async readOnly(on: boolean): Promise<Operations.State> {
    if (this._state.readOnly.on === on) return this.snapshot()
    this._state.readOnly = on ? { on: true, since: Date.now() } : { on: false }
    await this._persist()
    // Emitted like maintenance: without it, an operator freezing writes across a fleet froze one node.
    await this._events.emit(on ? 'readonly.on' : 'readonly.off', {})
    return this.snapshot()
  }

  /** Throws the AuthError whose `handleError` path carries the right status and retry hint.
   *  WARN: nothing calls this. Every adapter this package ships dispatches without it, so both switches
   *  gate only the routes a host guards itself. */
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
    // Normalised here rather than at the throw, so the stored state, the emitted event and the error meta
    // cannot disagree. Clamped rather than refused: maintenance going on is what matters during an incident
    // and a bad retry hint is advisory, where failing the call would leave the fleet serving traffic.
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

/** Constructs {@link OperationsImpl}. */
export function operations(events: Events.IBus, store?: Operations.Store): OperationsImpl {
  return new OperationsImpl(events, store)
}
