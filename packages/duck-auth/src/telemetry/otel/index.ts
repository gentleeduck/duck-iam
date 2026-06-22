/**
 * OpenTelemetry instrumentation for `@gentleduck/auth`. Wires the
 * AuthEvents bus into OTel metrics (counters + gauges + histograms) so
 * sign-in / session / lockout traffic surfaces in any
 * OpenTelemetry-compatible backend (Datadog, Grafana, Honeycomb, etc.).
 *
 * Tracing-side instrumentation is intentionally out of scope here:
 * use the framework's own OTel auto-instrumentation (express, hono,
 * etc.) - this module only adds the auth-domain metrics those traces
 * cannot derive on their own.
 */

import { AuthErrorObject } from '../../core/errors'
import type { AuthEvents } from '../../core/types/events'

/**
 * Records auth-domain metrics off an AuthEvents.IBus. The recorded
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
 */
export class AuthOtelInstrumentation {
  private readonly _signinTotal: AuthOtelInstrumentation.ICounter
  private readonly _signupTotal: AuthOtelInstrumentation.ICounter
  private readonly _sessionActive: AuthOtelInstrumentation.ICounter
  private readonly _sessionRotated: AuthOtelInstrumentation.ICounter
  private readonly _lockoutTotal: AuthOtelInstrumentation.ICounter
  private readonly _mfaEnrolled: AuthOtelInstrumentation.ICounter
  private readonly _mfaRemoved: AuthOtelInstrumentation.ICounter
  private readonly _impersonated: AuthOtelInstrumentation.ICounter
  private readonly _suspicious: AuthOtelInstrumentation.ICounter
  private readonly _defaults: Record<string, string | number | boolean>

  constructor(cfg: AuthOtelInstrumentation.IConfig) {
    if (!cfg.meter) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', {
        detail: 'AuthOtelInstrumentation requires a meter from @opentelemetry/api',
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
      description: 'AuthSession rotations',
    })
    this._lockoutTotal = cfg.meter.createCounter(`${p}.lockout.total`, {
      description: 'AuthIdentity lockouts',
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
      description: 'AuthAnomaly signals fired',
    })
  }

  /**
   * Subscribe to every event the lib emits that maps to a metric.
   * Returns a cleanup function that detaches every listener.
   */
  attach(bus: AuthEvents.IBus): () => void {
    const subs: AuthEvents.Unsubscribe[] = []

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
 */
export async function authGetOtelMeter(name = '@gentleduck/auth'): Promise<AuthOtelInstrumentation.IMeter> {
  try {
    const otel = (await import('@opentelemetry/api' as string)) as {
      metrics: { getMeter: (name: string) => AuthOtelInstrumentation.IMeter }
    }
    return otel.metrics.getMeter(name)
  } catch {
    throw new AuthErrorObject('AUTH/MISCONFIGURED', {
      detail:
        'authGetOtelMeter requires the `@opentelemetry/api` peerDep. ' + 'Install via `bun add @opentelemetry/api`.',
    })
  }
}

export namespace AuthOtelInstrumentation {
  export interface IConfig {
    /**
     * Meter to record against. Production: `metrics.getMeter('@gentleduck/auth')`
     * from `@opentelemetry/api`. Tests: any stub satisfying `OtelMeterLike`.
     */
    meter: AuthOtelInstrumentation.IMeter
    /** Metric name prefix. Default `auth`. Final names look like `auth.signin.total`. */
    prefix?: string
    /**
     * Extra attributes attached to every recorded measurement (env,
     * service.name, etc.). Useful when the meter does not auto-resource
     * those.
     */
    defaultAttributes?: Record<string, string | number | boolean>
  }

  export interface IMeter {
    createCounter(name: string, options?: { description?: string; unit?: string }): AuthOtelInstrumentation.ICounter
    createUpDownCounter(
      name: string,
      options?: { description?: string; unit?: string },
    ): AuthOtelInstrumentation.ICounter
    createHistogram(name: string, options?: { description?: string; unit?: string }): AuthOtelInstrumentation.IHistogram
  }

  export interface ICounter {
    add(value: number, attributes?: Record<string, string | number | boolean>): void
  }

  export interface IHistogram {
    record(value: number, attributes?: Record<string, string | number | boolean>): void
  }
}
