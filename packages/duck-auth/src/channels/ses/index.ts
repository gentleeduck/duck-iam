/**
 * @packageDocumentation
 * AWS SES channel adapter. Wraps `@aws-sdk/client-ses` (lazy peerDep)
 * via `SendEmailCommand` for kind:'email' delivery.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { AuthErrorObject } from '../../core/errors'
import type { Channel } from '../../core/types/channel'

/**
 * Subset of the SES v3 SDK we depend on. Only `send(SendEmailCommand)`
 * is required; consumers can supply a stub satisfying this shape.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface SesClientLike {
  send(command: { input: unknown }): Promise<{ MessageId?: string }>
}

/** Template resolver. Apps own all template content. */
export type SesTemplateResolver = (
  templateId: string,
  vars: Record<string, unknown>,
) => Promise<{ subject: string; text?: string; html?: string }> | { subject: string; text?: string; html?: string }

/**
 * Config knobs for `SesChannel`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface SesChannelConfig {
  /** Pre-built SESv3 client. Required (the SDK takes a region + credentials chain). */
  client: SesClientLike
  /** From: address; must be on a verified SES identity. */
  from: string
  /** Template resolver invoked per send. */
  templates: SesTemplateResolver
  /** Identifier appearing in logs + diagnostics. Default `ses`. */
  id?: string
  /** Optional configuration-set name (used for SES feedback notifications). */
  configurationSetName?: string
}

let _sesSendEmailCommand: (new (input: unknown) => { input: unknown }) | null = null
async function loadSendEmailCommand(): Promise<new (input: unknown) => { input: unknown }> {
  if (_sesSendEmailCommand) return _sesSendEmailCommand
  try {
    const mod = (await import('@aws-sdk/client-ses' as string)) as {
      SendEmailCommand: new (input: unknown) => { input: unknown }
    }
    _sesSendEmailCommand = mod.SendEmailCommand
    return mod.SendEmailCommand
  } catch {
    throw new AuthErrorObject('AUTH/MISCONFIGURED', {
      detail: 'SesChannel requires the `@aws-sdk/client-ses` peerDep. ' + 'Install via `bun add @aws-sdk/client-ses`.',
    })
  }
}

/**
 * SES channel implementation. Reads recipient email from
 * `identity.profile.email`; returns ok:false (never throws) on any
 * SES error so the caller can retry or escalate without exception
 * escape.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export class SesChannel implements Channel.IChannel {
  readonly kind: Channel.Kind = 'email'
  readonly id: string
  private readonly _cfg: SesChannelConfig

  constructor(cfg: SesChannelConfig) {
    if (!cfg.from) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', {
        detail: 'SesChannel requires a non-empty `from` address (must be a verified SES identity)',
      })
    }
    if (!cfg.client) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', {
        detail: 'SesChannel requires a pre-built client (SESClient from @aws-sdk/client-ses)',
      })
    }
    this._cfg = cfg
    this.id = cfg.id ?? 'ses'
  }

  /**
   * Render the template, build a SendEmailCommand, hand to SES.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async send(input: Channel.SendInput): Promise<Channel.SendResult> {
    const profile = input.identity.profile as { email?: string } | undefined
    const to = profile?.email
    if (!to) {
      return { ok: false, error: 'identity has no email; SesChannel cannot deliver' }
    }
    let resolved: Awaited<ReturnType<SesTemplateResolver>>
    try {
      resolved = await this._cfg.templates(input.templateId, input.vars as Record<string, unknown>)
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) }
    }
    try {
      const SendEmailCommand = await loadSendEmailCommand()
      const cmd = new SendEmailCommand({
        Source: this._cfg.from,
        Destination: { ToAddresses: [to] },
        Message: {
          Subject: { Data: resolved.subject, Charset: 'UTF-8' },
          Body: {
            ...(resolved.text !== undefined && {
              Text: { Data: resolved.text, Charset: 'UTF-8' },
            }),
            ...(resolved.html !== undefined && {
              Html: { Data: resolved.html, Charset: 'UTF-8' },
            }),
          },
        },
        ...(this._cfg.configurationSetName !== undefined && {
          ConfigurationSetName: this._cfg.configurationSetName,
        }),
      })
      const response = await this._cfg.client.send(cmd)
      const out: Channel.SendResult = { ok: true }
      if (response.MessageId !== undefined) out.providerMessageId = response.MessageId
      return out
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) }
    }
  }
}

/**
 * Namespace merge for `SesChannel`. Co-locates config + helpers.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace SesChannel {
  /** Alias for `SesChannelConfig`. */
  export type IConfig = SesChannelConfig
  /** Alias for `SesClientLike`. */
  export type IClient = SesClientLike
  /** Alias for `SesTemplateResolver`. */
  export type ITemplateResolver = SesTemplateResolver
}
