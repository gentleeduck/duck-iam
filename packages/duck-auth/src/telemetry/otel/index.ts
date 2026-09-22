/** OpenTelemetry instrumentation: wires the Events bus into OTel metrics so sign-in, session and lockout traffic
 *  surfaces in any compatible backend. Tracing is out of scope: the framework's own auto-instrumentation covers
 *  that, and this adds only the auth-domain metrics those traces cannot derive. */

import { AuthError } from '~/core/errors'
import type { Events } from '~/core/events'

/**
 * Records auth-domain metrics off an `Events.IBus`. `attach(bus)` subscribes and the returned cleanup detaches
 * every listener. The recorded surface:
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

  constructor(cfg: AuthOtelInstrumentation.Cfg) {
    if (!cfg.meter) {
      throw new AuthError('AUTH_MISCONFIGURED', {
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

/** Lazily load `@opentelemetry/api` and return a meter named after the library, throwing AUTH_MISCONFIGURED when
 *  the peer is missing. */
export async function authGetOtelMeter(name = '@gentleduck/auth'): Promise<AuthOtelInstrumentation.IMeter> {
  try {
    const otel = (await import('@opentelemetry/api' as string)) as {
      metrics: { getMeter: (name: string) => AuthOtelInstrumentation.IMeter }
    }
    return otel.metrics.getMeter(name)
  } catch {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail:
        'authGetOtelMeter requires the `@opentelemetry/api` peerDep. ' + 'Install via `bun add @opentelemetry/api`.',
    })
  }
}

/** Configuration for the OpenTelemetry instrumentation. */
export namespace AuthOtelInstrumentation {
  export interface Cfg {
    /**
     * Meter to record against. Production: `metrics.getMeter('@gentleduck/auth')`
     * from `@opentelemetry/api`. Tests: any stub satisfying `AuthOtelInstrumentation.IMeter`.
     */
    meter: AuthOtelInstrumentation.IMeter
    /** Metric name prefix. Default `auth`. Final names look like `auth.signin.total`. */
    prefix?: string
    /** Extra attributes on every recorded measurement, for a meter that does not auto-resource them. */
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

/** Constructs an {@link AuthOtelInstrumentation}. */
export function authOtelInstrumentation(
  ...args: ConstructorParameters<typeof AuthOtelInstrumentation>
): AuthOtelInstrumentation {
  return new AuthOtelInstrumentation(...args)
}
