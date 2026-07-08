/**
 * Console channel - logs every outbound message to stdout / a supplied
 * sink. Built for local development + tests; never wire into production.
 */

import type { Channel } from '~/core/types/infra'

export namespace AuthConsoleChannel {
  /**
   * Sink function signature. Default writes to process.stdout via
   * `console.log`; tests inject a spy to assert what was sent.
   */
  export type ISink = (line: string) => void

  /** Config for the channel. */
  export interface IConfig {
    /** `email` | `sms` | `webpush`. Default `email`. */
    kind?: Channel.Kind
    /** Identifier appearing in logs + diagnostics. Default `console`. */
    id?: string
    /** Override the sink (e.g. for tests). Default `console.log`. */
    sink?: ISink
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
  readonly kind: Channel.Kind
  readonly id: string
  private readonly _sink: AuthConsoleChannel.ISink

  constructor(cfg: AuthConsoleChannel.IConfig = {}) {
    this.kind = cfg.kind ?? 'email'
    this.id = cfg.id ?? 'console'
    this._sink = cfg.sink ?? ((line) => console.log(line))
  }

  /**
   * Serialize the send envelope to a single JSON line and flush. PII is
   * redacted before logging: the identity's profile is stringified to
   * `<identityId>` only; full payloads stay in the `vars` field which
   * the caller controls.
   */
  async send(input: Channel.SendInput): Promise<Channel.SendResult> {
    const messageId = `console:${Date.now()}:${Math.random().toString(36).slice(2, 10)}`
    this._sink(
      JSON.stringify({
        channel: this.kind,
        id: this.id,
        messageId,
        templateId: input.templateId,
        identityId: input.identity.id,
        tenantId: input.tenant.tenantId ?? null,
        vars: input.vars,
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
  readonly kind: Channel.Kind
  readonly id: string

  constructor(cfg: AuthNoopChannel.IConfig = {}) {
    this.kind = cfg.kind ?? 'email'
    this.id = cfg.id ?? 'noop'
  }

  /** Drop the send on the floor. Always returns ok with a stub message id. */
  async send(_input: Channel.SendInput): Promise<Channel.SendResult> {
    return { ok: true, providerMessageId: `noop:${Date.now()}` }
  }
}

export namespace AuthNoopChannel {
  export interface IConfig {
    kind?: Channel.Kind
    id?: string
  }
}

/**
 * Captures every send into an in-memory array. The intended consumer is
 * `vitest`; production code must not use this channel.
 */
export class AuthTestChannel implements Channel.Channel {
  readonly kind: Channel.Kind
  readonly id: string
  readonly outbox: AuthTestChannel.IOutboxEntry[] = []

  constructor(cfg: AuthTestChannel.IConfig = {}) {
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

export namespace AuthTestChannel {
  export interface IConfig {
    kind?: Channel.Kind
    id?: string
  }
  export interface IOutboxEntry {
    templateId: string
    identityId: string
    tenantId: string | null
    vars: Record<string, unknown>
  }
}
