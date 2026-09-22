/** Logs every outbound message to stdout or a supplied sink. Development and tests only. */

import { randomUUID } from 'node:crypto'
import { env } from 'node:process'
import type { Channel } from '~/channels/channels.types'
import { AuthError, redactSecrets } from '~/core/errors'

/**
 * Same shape as `AuthNullCaptchaVerifier`: each of these is exported from the package and satisfies
 * the channel interface, so nothing but this stops one being wired where real delivery was meant.
 */
function refuseInProduction(name: string, what: string, development?: boolean): void {
  if (env.NODE_ENV === 'production' && !development) {
    throw new AuthError('AUTH_MISCONFIGURED', { detail: `${name} ${what} and is not production ready` })
  }
}

/**
 * Published by all three, so `AuthEngine.strict()` can refuse them the way it already refuses
 * `AuthNullCaptchaVerifier`, `AuthMemoryIdempotency` and the memory adapter.
 *
 * SECURITY: the check above is the whole of the defence otherwise, and it only fires when `NODE_ENV`
 * says `production` - which is the deploy `strict()`'s idempotency and captcha checks exist to catch,
 * both of those carrying a brand for exactly this reason. What got through: a channel that writes every
 * magic link and one-time code to a log, one that answers `ok` for a password reset it dropped, and one
 * that keeps every message in a process-lifetime array. Read as a brand and not by constructor name,
 * since a host's own wrapper is a channel too.
 */
const NON_DELIVERING_CHANNEL = '__isNonDeliveringChannel' as const

export namespace AuthConsoleChannel {
  /**
   * Sink function signature. Default writes to process.stdout via
   * `console.log`; tests inject a spy to assert what was sent.
   */
  export type ISink = (line: string) => void

  /** Cfg for the channel. */
  export interface Cfg {
    /** `email` | `sms` | `webpush`. Default `email`. */
    kind?: Channel.Kind
    /** Identifier appearing in logs + diagnostics. Default `console`. */
    id?: string
    /** Override the sink (e.g. for tests). Default `console.log`. */
    sink?: ISink
    /** Escape hatch to allow this channel under `NODE_ENV=production`. */
    development?: boolean
  }
}

/**
 * Reference channel implementation. Emits one JSON line per send so
 * downstream log aggregators (vector, fluent-bit) can parse without an
 * intermediate codec. Returns ok:true with a deterministic
 * `providerMessageId` of the form `console:<nanos>:<random>` for
 * diagnostics-friendly correlation in tests.
 */
export class AuthConsoleChannel implements Channel.Channel {
  /** Writes every message it is given to a log; read by `strict()`. */
  readonly [NON_DELIVERING_CHANNEL] = true as const
  readonly kind: Channel.Kind
  readonly id: string
  private readonly _sink: AuthConsoleChannel.ISink

  constructor(cfg: AuthConsoleChannel.Cfg = {}) {
    refuseInProduction('AuthConsoleChannel', 'writes every message to a log', cfg.development)
    this.kind = cfg.kind ?? 'email'
    this.id = cfg.id ?? 'console'
    this._sink = cfg.sink ?? ((line) => console.log(line))
  }

  /**
   * Serialises the send envelope to a single JSON line and flushes it. The profile is reduced to the
   * identity id, and `vars` is redacted by key name.
   * SECURITY: `vars` carries the signed magic link and the one-time code, so logging it whole puts a
   * working credential in stdout.
   */
  async send(input: Channel.SendInput): Promise<Channel.SendResult> {
    const messageId = `console:${Date.now()}:${randomUUID()}`
    this._sink(
      JSON.stringify({
        channel: this.kind,
        id: this.id,
        messageId,
        templateId: input.templateId,
        identityId: input.identity.id,
        tenantId: input.tenant.tenantId ?? null,
        vars: redactSecrets(input.vars),
      }),
    )
    return { ok: true, providerMessageId: messageId }
  }
}

/**
 * No-op channel. Discards every send, always reports ok. Useful for
 * tenants on a free plan where the magic-link / verification email is
 * gated to the in-product inbox only.
 */
export class AuthNoopChannel implements Channel.Channel {
  /** Reports every send as delivered without making one; read by `strict()`. */
  readonly [NON_DELIVERING_CHANNEL] = true as const
  readonly kind: Channel.Kind
  readonly id: string

  constructor(cfg: AuthNoopChannel.Cfg = {}) {
    refuseInProduction('AuthNoopChannel', 'reports every send as delivered', cfg.development)
    this.kind = cfg.kind ?? 'email'
    this.id = cfg.id ?? 'noop'
  }

  /**
   * Drop the send on the floor. No `providerMessageId`: a caller storing one for support
   * diagnostics was recording a delivery that never happened.
   */
  async send(_input: Channel.SendInput): Promise<Channel.SendResult> {
    return { ok: true }
  }
}

/** Configuration for the no-op channel. */
export namespace AuthNoopChannel {
  export interface Cfg {
    kind?: Channel.Kind
    id?: string
    /** Escape hatch to allow this channel under `NODE_ENV=production`. */
    development?: boolean
  }
}

/**
 * Captures every send into an in-memory array. The intended consumer is
 * `vitest`; production code must not use this channel.
 */
export class AuthTestChannel implements Channel.Channel {
  /** Keeps every message in memory and delivers none; read by `strict()`. */
  readonly [NON_DELIVERING_CHANNEL] = true as const
  readonly kind: Channel.Kind
  readonly id: string
  readonly outbox: AuthTestChannel.IOutboxEntry[] = []

  constructor(cfg: AuthTestChannel.Cfg = {}) {
    refuseInProduction('AuthTestChannel', 'keeps every message in memory', cfg.development)
    this.kind = cfg.kind ?? 'email'
    this.id = cfg.id ?? 'test'
  }

  /**
   * Append the send envelope to `this.outbox` for later assertion;
   * always returns ok.
   */
  async send(input: Channel.SendInput): Promise<Channel.SendResult> {
    this.outbox.push({
      templateId: input.templateId,
      identityId: input.identity.id,
      tenantId: input.tenant.tenantId ?? null,
      vars: input.vars,
    })
    return { ok: true, providerMessageId: `test:${this.outbox.length}` }
  }
}

/** Configuration for the recording test channel. */
export namespace AuthTestChannel {
  export interface Cfg {
    kind?: Channel.Kind
    id?: string
    /** Escape hatch to allow this channel under `NODE_ENV=production`. */
    development?: boolean
  }
  export interface IOutboxEntry {
    templateId: string
    identityId: string
    tenantId: string | null
    vars: Record<string, unknown>
  }
}

/** Writes each message to the console. For local development. */
export function authConsoleChannel(...args: ConstructorParameters<typeof AuthConsoleChannel>): AuthConsoleChannel {
  return new AuthConsoleChannel(...args)
}

/** Drops every message. */
export function authNoopChannel(...args: ConstructorParameters<typeof AuthNoopChannel>): AuthNoopChannel {
  return new AuthNoopChannel(...args)
}

/** Records every message in memory so a test can assert on what was sent. */
export function authTestChannel(...args: ConstructorParameters<typeof AuthTestChannel>): AuthTestChannel {
  return new AuthTestChannel(...args)
}
