/**
 * @packageDocumentation
 * OpenTelemetry instrumentation for `@gentleduck/auth`. Wires the
 * Events bus into OTel metrics (counters + gauges + histograms) so
 * sign-in / session / lockout traffic surfaces in any
 * OpenTelemetry-compatible backend (Datadog, Grafana, Honeycomb, etc.).
 *
 * Tracing-side instrumentation is intentionally out of scope here:
 * use the framework's own OTel auto-instrumentation (express, hono,
 * etc.) - this module only adds the auth-domain metrics those traces
 * cannot derive on their own.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { AuthErrorObject } from '../../core/errors'
import type { Events } from '../../core/types/events'

/**
 * Narrow subset of `@opentelemetry/api` Meter we use. Lets consumers
 * pass any meter implementation (real OTel SDK, test stub, custom
 * forwarder) without the auth lib taking @opentelemetry/api as a hard
 * dep.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface OtelMeterLike {
  createCounter(name: string, options?: { description?: string; unit?: string }): OtelCounterLike
  createUpDownCounter(name: string, options?: { description?: string; unit?: string }): OtelCounterLike
  createHistogram(name: string, options?: { description?: string; unit?: string }): OtelHistogramLike
}

export interface OtelCounterLike {
  add(value: number, attributes?: Record<string, string | number | boolean>): void
}

export interface OtelHistogramLike {
  record(value: number, attributes?: Record<string, string | number | boolean>): void
}

/**
 * Config knobs for `OtelInstrumentation`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface OtelInstrumentationConfig {
  /**
   * Meter to record against. Production: `metrics.getMeter('@gentleduck/auth')`
   * from `@opentelemetry/api`. Tests: any stub satisfying `OtelMeterLike`.
   */
  meter: OtelMeterLike
  /** Metric name prefix. Default `auth`. Final names look like `auth.signin.total`. */
  prefix?: string
  /**
   * Extra attributes attached to every recorded measurement (env,
   * service.name, etc.). Useful when the meter does not auto-resource
   * those.
   */
  defaultAttributes?: Record<string, string | number | boolean>
}

/**
 * Records auth-domain metrics off an Events.IBus. The recorded
 * surface:
 *
 *   - {prefix}.signin.total (counter): tag provider + result (success / failed)
 *   - {prefix}.signup.total (counter)
 *   - {prefix}.session.active (up-down counter): incremented on session.created,
 *     decremented on session.revoked
 *   - {prefix}.session.rotated.total (counter)
 *   - {prefix}.lockout.total (counter): tag identityId
 *   - {prefix}.mfa.enrolled.total / mfa.removed.total (counters)
 *   - {prefix}.identity.impersonated.total (counter)
 *   - {prefix}.suspicious.total (counter): tag signal + score-bucket
 *
 * `attach(bus)` subscribes; the returned cleanup detaches every listener.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export class OtelInstrumentation {
  private readonly _signinTotal: OtelCounterLike
  private readonly _signupTotal: OtelCounterLike
  private readonly _sessionActive: OtelCounterLike
  private readonly _sessionRotated: OtelCounterLike
  private readonly _lockoutTotal: OtelCounterLike
  private readonly _mfaEnrolled: OtelCounterLike
  private readonly _mfaRemoved: OtelCounterLike
  private readonly _impersonated: OtelCounterLike
  private readonly _suspicious: OtelCounterLike
  private readonly _defaults: Record<string, string | number | boolean>

  constructor(cfg: OtelInstrumentationConfig) {
    if (!cfg.meter) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', {
        detail: 'OtelInstrumentation requires a meter from @opentelemetry/api',
      })
    }
    const p = cfg.prefix ?? 'auth'
    this._defaults = cfg.defaultAttributes ?? {}
    this._signinTotal = cfg.meter.createCounter(`${p}.signin.total`, {
      description: 'Sign-in attempts by provider + result',
    })
    this._signupTotal = cfg.meter.createCounter(`${p}.signup.total`, {
      description: 'Sign-up completions',
    })
    this._sessionActive = cfg.meter.createUpDownCounter(`${p}.session.active`, {
      description: 'Currently active sessions (best-effort: incremented on create, decremented on revoke)',
    })
    this._sessionRotated = cfg.meter.createCounter(`${p}.session.rotated.total`, {
      description: 'Session rotations',
    })
    this._lockoutTotal = cfg.meter.createCounter(`${p}.lockout.total`, {
      description: 'Identity lockouts',
    })
    this._mfaEnrolled = cfg.meter.createCounter(`${p}.mfa.enrolled.total`, {
      description: 'MFA methods enrolled',
    })
    this._mfaRemoved = cfg.meter.createCounter(`${p}.mfa.removed.total`, {
      description: 'MFA methods removed',
    })
    this._impersonated = cfg.meter.createCounter(`${p}.identity.impersonated.total`, {
      description: 'Impersonation sessions started',
    })
    this._suspicious = cfg.meter.createCounter(`${p}.suspicious.total`, {
      description: 'Anomaly signals fired',
    })
  }

  /**
   * Subscribe to every event the lib emits that maps to a metric.
   * Returns a cleanup function that detaches every listener.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  attach(bus: Events.IBus): () => void {
    const subs: Events.Unsubscribe[] = []

    subs.push(
      bus.on('signin.success', (payload) => {
        this._signinTotal.add(1, {
          ...this._defaults,
          provider: payload.factors[0]?.method ?? 'unknown',
          result: 'success',
        })
      }),
    )
    subs.push(
      bus.on('signin.failed', (payload) => {
        this._signinTotal.add(1, {
          ...this._defaults,
          provider: payload.providerId,
          result: 'failed',
          reason: payload.reason,
        })
      }),
    )
    subs.push(
      bus.on('signup.completed', () => {
        this._signupTotal.add(1, this._defaults)
      }),
    )
    subs.push(
      bus.on('session.created', () => {
        this._sessionActive.add(1, this._defaults)
      }),
    )
    subs.push(
      bus.on('session.revoked', () => {
        this._sessionActive.add(-1, this._defaults)
      }),
    )
    subs.push(
      bus.on('session.rotated', () => {
        this._sessionRotated.add(1, this._defaults)
      }),
    )
    subs.push(
      bus.on('lockout', () => {
        this._lockoutTotal.add(1, this._defaults)
      }),
    )
    subs.push(
      bus.on('mfa.enrolled', (payload) => {
        this._mfaEnrolled.add(1, { ...this._defaults, method: payload.method })
      }),
    )
    subs.push(
      bus.on('mfa.removed', (payload) => {
        this._mfaRemoved.add(1, { ...this._defaults, method: payload.method })
      }),
    )
    subs.push(
      bus.on('identity.impersonated', () => {
        this._impersonated.add(1, this._defaults)
      }),
    )
    subs.push(
      bus.on('suspicious', (payload) => {
        this._suspicious.add(1, {
          ...this._defaults,
          signal: payload.signal,
          severity: bucketSeverity(payload.score),
        })
      }),
    )

    return () => {
      for (const off of subs) off()
    }
  }
}

function bucketSeverity(score: number): 'low' | 'medium' | 'high' {
  if (score < 0.33) return 'low'
  if (score < 0.66) return 'medium'
  return 'high'
}

/**
 * Convenience: tries to load `@opentelemetry/api` lazily + return a
 * meter named after the auth lib. Throws AUTH/MISCONFIGURED when the
 * peer is missing.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export async function getAuthOtelMeter(name = '@gentleduck/auth'): Promise<OtelMeterLike> {
  try {
    const otel = (await import('@opentelemetry/api' as string)) as {
      metrics: { getMeter: (name: string) => OtelMeterLike }
    }
    return otel.metrics.getMeter(name)
  } catch {
    throw new AuthErrorObject('AUTH/MISCONFIGURED', {
      detail:
        'getAuthOtelMeter requires the `@opentelemetry/api` peerDep. ' + 'Install via `bun add @opentelemetry/api`.',
    })
  }
}

/**
 * Namespace merge for `OtelInstrumentation`. Co-locates config + meter
 * + instrument contracts alongside the class.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace OtelInstrumentation {
  /** Alias for `OtelInstrumentationConfig`. */
  export type IConfig = OtelInstrumentationConfig
  /** Alias for `OtelMeterLike`. */
  export type IMeter = OtelMeterLike
  /** Alias for `OtelCounterLike`. */
  export type ICounter = OtelCounterLike
  /** Alias for `OtelHistogramLike`. */
  export type IHistogram = OtelHistogramLike
}
