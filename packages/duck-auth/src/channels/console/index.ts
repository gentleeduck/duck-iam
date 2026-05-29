/**
 * @packageDocumentation
 * Console channel - logs every outbound message to stdout / a supplied
 * sink. Built for local development + tests; never wire into production.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import type { Channel } from '../../core/types/channel'

/**
 * Sink function signature. Default writes to process.stdout via
 * `console.log`; tests inject a spy to assert what was sent.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export type ConsoleSink = (line: string) => void

/** Config for `ConsoleChannel`. */
export interface ConsoleChannelConfig {
  /** `email` | `sms` | `webpush`. Default `email`. */
  kind?: Channel.Kind
  /** Identifier appearing in logs + diagnostics. Default `console`. */
  id?: string
  /** Override the sink (e.g. for tests). Default `console.log`. */
  sink?: ConsoleSink
}

/**
 * Reference channel implementation. Emits one JSON line per send so
 * downstream log aggregators (vector, fluent-bit) can parse without an
 * intermediate codec. Returns ok:true with a deterministic
 * `providerMessageId` of the form `console:<nanos>:<random>` for
 * diagnostics-friendly correlation in tests.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export class ConsoleChannel implements Channel.IChannel {
  readonly kind: Channel.Kind
  readonly id: string
  private readonly _sink: ConsoleSink

  constructor(cfg: ConsoleChannelConfig = {}) {
    this.kind = cfg.kind ?? 'email'
    this.id = cfg.id ?? 'console'
    this._sink = cfg.sink ?? ((line) => console.log(line))
  }

  /**
   * Serialize the send envelope to a single JSON line and flush. PII is
   * redacted before logging: the identity's profile is stringified to
   * `<identityId>` only; full payloads stay in the `vars` field which
   * the caller controls.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
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
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export class NoopChannel implements Channel.IChannel {
  readonly kind: Channel.Kind
  readonly id: string

  constructor(cfg: { kind?: Channel.Kind; id?: string } = {}) {
    this.kind = cfg.kind ?? 'email'
    this.id = cfg.id ?? 'noop'
  }

  /**
   * Drop the send on the floor. Always returns ok with a stub message id.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async send(_input: Channel.SendInput): Promise<Channel.SendResult> {
    return { ok: true, providerMessageId: `noop:${Date.now()}` }
  }
}

/**
 * Captures every send into an in-memory array. The intended consumer is
 * `vitest`; production code must not use this channel.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export class TestChannel implements Channel.IChannel {
  readonly kind: Channel.Kind
  readonly id: string
  readonly outbox: Array<{
    templateId: string
    identityId: string
    tenantId: string | null
    vars: Record<string, unknown>
  }> = []

  constructor(cfg: { kind?: Channel.Kind; id?: string } = {}) {
    this.kind = cfg.kind ?? 'email'
    this.id = cfg.id ?? 'test'
  }

  /**
   * Append the send envelope to `this.outbox` for later assertion;
   * always returns ok.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async send(input: Channel.SendInput): Promise<Channel.SendResult> {
    this.outbox.push({
      templateId: input.templateId,
      identityId: input.identity.id,
      tenantId: input.tenant.tenantId ?? null,
      vars: input.vars as Record<string, unknown>,
    })
    return { ok: true, providerMessageId: `test:${this.outbox.length}` }
  }
}

/**
 * Namespace merge for `ConsoleChannel`. Co-locates config alongside
 * the class via TS class+namespace merging.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace ConsoleChannel {
  /** Alias for `ConsoleChannelConfig`. */
  export type IConfig = ConsoleChannelConfig
  /** Alias for `ConsoleSink`. */
  export type ISink = ConsoleSink
}
