/**
 * AWS SES channel adapter. Wraps `@aws-sdk/client-ses` (lazy peerDep)
 * via `SendEmailCommand` for kind:'email' delivery.
 */

import { getProfileString } from '../../core/credential-utils'
import { AuthError } from '../../core/errors'
import type { Channel } from '../../core/types/infra'

export namespace AuthSesChannel {
  /** Subset of the SES v3 SDK we depend on. */
  export interface IClient {
    send(command: { input: unknown }): Promise<{ MessageId?: string }>
  }

  /** Template resolver. */
  export type ITemplateResolver = (
    templateId: string,
    vars: Record<string, unknown>,
  ) => Promise<{ subject: string; text?: string; html?: string }> | { subject: string; text?: string; html?: string }

  /** Config knobs for {@link AuthSesChannel}. */
  export interface IConfig<TClient extends IClient = IClient> {
    /** Pre-built SESv3 client. Required. */
    client: TClient
    /** From: address; must be on a verified SES identity. */
    from: string
    /** Template resolver invoked per send. */
    templates: ITemplateResolver
    /** Identifier appearing in logs + diagnostics. Default `ses`. */
    id?: string
    /** Optional configuration-set name (SES feedback notifications). */
    configurationSetName?: string
  }
}

let _sesSendEmailCommand: (new (input: unknown) => { input: unknown }) | null = null
async function loadSendEmailCommand(): Promise<new (input: unknown) => { input: unknown }> {
  if (_sesSendEmailCommand) return _sesSendEmailCommand
  try {
    const mod = await import('@aws-sdk/client-ses' as string)
    _sesSendEmailCommand = mod.SendEmailCommand
    return mod.SendEmailCommand
  } catch {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: 'AuthSesChannel requires the `@aws-sdk/client-ses` peerDep. Install via `bun add @aws-sdk/client-ses`.',
    })
  }
}

/**
 * SES channel implementation. Reads recipient email from
 * `identity.profile.email`; returns ok:false on any SES error.
 */
export class AuthSesChannel<TClient extends AuthSesChannel.IClient = AuthSesChannel.IClient>
  implements Channel.IChannel
{
  readonly kind: Channel.Kind = 'email'
  readonly id: string
  private readonly _cfg: AuthSesChannel.IConfig<TClient>

  constructor(cfg: AuthSesChannel.IConfig<TClient>) {
    if (!cfg.from) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: 'AuthSesChannel requires a non-empty `from` address (must be a verified SES identity)',
      })
    }
    if (!cfg.client) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: 'AuthSesChannel requires a pre-built client (SESClient from @aws-sdk/client-ses)',
      })
    }
    this._cfg = cfg
    this.id = cfg.id ?? 'ses'
  }

  /** Render the template, build a SendEmailCommand, hand to SES. */
  async send(input: Channel.SendInput): Promise<Channel.SendResult> {
    const to = getProfileString(input.identity.profile, 'email')
    if (!to) {
      return { ok: false, error: 'identity has no email; AuthSesChannel cannot deliver' }
    }
    let resolved: Awaited<ReturnType<AuthSesChannel.ITemplateResolver>>
    try {
      resolved = await this._cfg.templates(input.templateId, input.vars)
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
