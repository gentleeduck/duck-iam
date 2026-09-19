/**
 * AWS SES channel adapter. Wraps `@aws-sdk/client-ses` (lazy peerDep)
 * via `SendEmailCommand` for kind:'email' delivery.
 */

import type { Channel } from '~/channels/channels.types'
import { AuthError } from '~/core/errors'
import { ChannelGuard } from '../channels.guard'
import { checkRenderedEmail, describeSendError, resolveEmailRecipient, sanitizeSubject } from '../channels.outbound'

export namespace AuthSesChannel {
  /** The subset of the SES v3 SDK this uses. */
  export interface IClient {
    send(command: { input: unknown }): Promise<{ MessageId?: string }>
  }

  /** Template resolver. */
  export interface Cfg<TClient extends IClient = IClient> extends ChannelGuard.Cfg {
    /** Pre-built SESv3 client. Required. */
    client: TClient
    /** From: address; must be on a verified SES identity. */
    from: string
    /** Template resolver invoked per send. */
    templates: Channel.IEmailTemplateResolver
    /** Identifier appearing in logs + diagnostics. Default `ses`. */
    id?: string
    /** Optional configuration-set name (SES feedback notifications). */
    configurationSetName?: string
    /**
     * The SDK's `SendEmailCommand`. Supplied together with a `client`, this is what makes the
     * peer dependency genuinely optional, which is the whole point of accepting a built client.
     */
    sendEmailCommand?: new (
      input: unknown,
    ) => { input: unknown }
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

/** A client the caller built needs no command class from here; a real SESClient rejects this envelope. */
class PlainCommand {
  constructor(readonly input: unknown) {}
}

/**
 * SES channel implementation. Reads recipient email from
 * `identity.profile.email`; returns ok:false on any SES error.
 */
export class AuthSesChannel<TClient extends AuthSesChannel.IClient = AuthSesChannel.IClient>
  implements Channel.Channel
{
  readonly kind: Channel.Kind = 'email'
  readonly id: string
  private readonly _cfg: AuthSesChannel.Cfg<TClient>
  private readonly _guard: ChannelGuard

  constructor(cfg: AuthSesChannel.Cfg<TClient>) {
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
    this._guard = new ChannelGuard(this.id, cfg)
  }

  /** Explicit first, then the SDK, then the plain envelope an injected client understands. */
  private async _command(): Promise<new (input: unknown) => { input: unknown }> {
    if (this._cfg.sendEmailCommand) return this._cfg.sendEmailCommand
    try {
      return await loadSendEmailCommand()
    } catch (err) {
      if (this._cfg.client) return PlainCommand
      throw err
    }
  }

  /** Render the template, build a SendEmailCommand, hand to SES. */
  async send(input: Channel.SendInput): Promise<Channel.SendResult> {
    const recipient = resolveEmailRecipient(input.identity.profile, 'AuthSesChannel')
    if (!recipient.ok) return { error: recipient.error, ok: false, retryable: false }
    const budget = await this._guard.spend(input).wrap()
    if (budget.error) return { error: budget.error.code, ok: false, retryable: true }
    const to = recipient.to
    let resolved: Awaited<ReturnType<Channel.IEmailTemplateResolver>>
    try {
      resolved = await this._cfg.templates(input.templateId, input.vars)
    } catch (err) {
      return { error: describeSendError(err), ok: false, retryable: false }
    }
    const malformed = checkRenderedEmail(resolved)
    if (malformed) return { error: `AuthSesChannel: ${malformed}`, ok: false, retryable: false }
    try {
      const SendEmailCommand = await this._command()
      const cmd = new SendEmailCommand({
        Source: this._cfg.from,
        Destination: { ToAddresses: [to] },
        Message: {
          Subject: { Charset: 'UTF-8', Data: sanitizeSubject(resolved.subject) },
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
      const response = await this._guard.attempt(() => this._cfg.client.send(cmd))
      const out: Channel.SendResult = { ok: true }
      if (response.MessageId !== undefined) out.providerMessageId = response.MessageId
      return out
    } catch (err) {
      return { error: describeSendError(err), ok: false, retryable: true }
    }
  }
}

/** Email channel over Amazon SES. */
export function authSesChannel(...args: ConstructorParameters<typeof AuthSesChannel>): AuthSesChannel {
  return new AuthSesChannel(...args)
}
