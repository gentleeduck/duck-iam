/**
 * Every channel carries the same payload: a signed magic link, a one-time code,
 * a reset URL. So the interesting questions are the same for all of them, and
 * are asked here once against each implementation rather than per adapter.
 *
 * Who is the recipient and who decided that. How much can be sent in one call,
 * given SMS is billed per segment and push has a hard payload ceiling. What a
 * failure reports, given `send` returns a result rather than throwing. And what
 * ends up in a log line.
 *
 * The per-channel suites cover each adapter's own wiring. These cover the
 * contract they share, and where it is thinner than it looks.
 *
 * Sources: RFC 8030 and RFC 8291 on the 4096-byte web-push payload ceiling,
 * E.164 on what a dialable number is, RFC 5321 section 4.5.3.1 on address
 * length, and OWASP's guidance on SMS pumping and outbound-message abuse.
 */
import { describe, expect, it, vi } from 'vitest'
import { AuthConsoleChannel, AuthNoopChannel } from '~/channels/console'
import { AuthResendChannel } from '~/channels/resend'
import { AuthSesChannel } from '~/channels/ses'
import { AuthSmtpChannel } from '~/channels/smtp'
import { AuthTwilioChannel } from '~/channels/twilio'
import { AuthWebPushChannel } from '~/channels/webpush'
import { AuthError } from '~/core/errors'
import { MemoryLimiter } from '~/limiters/memory'
import type { Channel } from '../channels.types'

type Profile = Record<string, unknown>

/** An identity carrying whatever recipient fields the case needs. */
function identity(profile: Profile = { email: 'user@app.test', phone: '+15550100' }) {
  return {
    createdAt: new Date(),
    deletedAt: null,
    id: 'ident-1',
    profile,
    providers: [],
    tenantId: null,
    updatedAt: new Date(),
    version: 1,
  } as never
}

const sendInput = (over: Partial<Channel.SendInput> = {}): Channel.SendInput => ({
  identity: identity(),
  templateId: 'magic-link',
  tenant: {},
  vars: { url: 'https://app.test/magic?token=SECRET-TOKEN' },
  ...over,
})

const emailTemplate = () => ({ html: '<p>hi</p>', subject: 'Sign in', text: 'hi' })

/** Each channel, built over a stub transport that records what it was handed. */
function buildAll() {
  const sent: Record<string, unknown[]> = {}
  const record = (id: string, payload: unknown) => {
    sent[id] = [...(sent[id] ?? []), payload]
  }

  const channels = {
    console: new AuthConsoleChannel({ sink: (line) => record('console', line) }),
    noop: new AuthNoopChannel(),
    resend: new AuthResendChannel({
      client: {
        emails: {
          send: async (opts) => {
            record('resend', opts)
            return { data: { id: 'resend-1' } }
          },
        },
      },
      from: 'noreply@app.test',
      templates: emailTemplate,
    }),
    ses: new AuthSesChannel({
      client: {
        send: async (command) => {
          record('ses', command.input)
          return { MessageId: 'ses-1' }
        },
      },
      from: 'noreply@app.test',
      templates: emailTemplate,
    }),
    smtp: new AuthSmtpChannel({
      from: 'noreply@app.test',
      templates: emailTemplate,
      transporter: {
        sendMail: async (opts) => {
          record('smtp', opts)
          return { messageId: 'smtp-1' }
        },
      },
    }),
    twilio: new AuthTwilioChannel({
      client: {
        messages: {
          create: async (opts) => {
            record('twilio', opts)
            return { sid: 'twilio-1' }
          },
        },
      },
      from: '+15550199',
      templates: () => ({ body: 'your code is 123456' }),
    }),
  }
  return { channels, sent }
}

const EMAIL_CHANNELS = ['resend', 'ses', 'smtp'] as const

describe('the shared contract every channel implements', () => {
  it('each reports a kind and an id', () => {
    const { channels } = buildAll()
    for (const [name, channel] of Object.entries(channels)) {
      expect(channel.id, name).toBeTruthy()
      expect(['email', 'sms', 'webpush'], name).toContain(channel.kind)
    }
  })

  it('a successful send reports ok', async () => {
    const { channels } = buildAll()
    for (const [name, channel] of Object.entries(channels)) {
      expect((await channel.send(sendInput())).ok, name).toBe(true)
    }
  })

  it('lets an injected client stand in for the sdk, which is what the option is for', async () => {
    // SES also reached for `SendEmailCommand`, so a caller who supplied a client still needed the
    // peer dependency and found out at delivery time.
    const { channels, sent } = buildAll()
    expect(await channels.ses.send(sendInput())).toMatchObject({ ok: true })
    expect(sent.ses).toHaveLength(1)
  })

  it('reports what is misconfigured, not just that something is', async () => {
    // `err.message` on an AuthError is the code; everything an operator needs, here the name of
    // the package to install, lives in `meta.detail`.
    const channel = new AuthSesChannel({
      client: { send: async () => ({ MessageId: 'x' }) },
      from: 'noreply@app.test',
      sendEmailCommand: class {
        constructor() {
          throw new AuthError('AUTH_MISCONFIGURED', { detail: 'AuthSesChannel needs @aws-sdk/client-ses' })
        }
      } as never,
      templates: emailTemplate,
    })
    const result = await channel.send(sendInput())
    expect(result.error).toContain('@aws-sdk/client-ses')
  })

  it('a missing recipient is a soft failure naming the channel', async () => {
    const { channels } = buildAll()
    const blank = sendInput({ identity: identity({}) })
    for (const name of [...EMAIL_CHANNELS, 'twilio'] as const) {
      const result = await channels[name].send(blank)
      expect(result, name).toMatchObject({ ok: false })
      expect(result.error, name).toContain('cannot deliver')
    }
  })

  it('reports a transport failure as retryable, so a caller can tell it from a wiring fault', async () => {
    const channel = new AuthSmtpChannel({
      from: 'noreply@app.test',
      retries: 0,
      templates: emailTemplate,
      transporter: {
        sendMail: async () => {
          throw new Error('connection refused')
        },
      },
    })
    await expect(channel.send(sendInput())).resolves.toMatchObject({
      error: 'connection refused',
      ok: false,
      retryable: true,
    })
  })

  it('keeps the credential out of the provider text it passes on', async () => {
    // SDK errors routinely include the request URL, the account identifier, and occasionally the
    // credential that was rejected.
    const leaky = 'Request to https://api.example/v1/send?apiKey=re_live_SECRET failed'
    const channel = new AuthResendChannel({
      client: {
        emails: {
          send: async () => ({ error: { message: leaky } }),
        },
      },
      from: 'noreply@app.test',
      templates: emailTemplate,
    })
    const error = (await channel.send(sendInput())).error
    expect(error).not.toContain('re_live_SECRET')
    expect(error).toContain('https://api.example/v1/send')
  })

  it('marks a template resolver that throws as not retryable', async () => {
    // A broken template is a programming error on the app's side. It used to land in the same
    // shape as a network outage, so retry logic keyed on the result retried what can never work.
    const channel = new AuthSmtpChannel({
      from: 'noreply@app.test',
      templates: () => {
        throw new Error('unknown templateId')
      },
      transporter: { sendMail: async () => ({ messageId: 'x' }) },
    })
    expect(await channel.send(sendInput())).toMatchObject({
      error: 'unknown templateId',
      ok: false,
      retryable: false,
    })
  })

  it('gives the transport a deadline, so a provider that never answers cannot park a login', async () => {
    // These sit inside password reset and MFA delivery, so the request holding one open is a user
    // waiting on a sign-in.
    const channel = new AuthSmtpChannel({
      from: 'noreply@app.test',
      retries: 0,
      templates: emailTemplate,
      timeoutMs: 20,
      transporter: { sendMail: () => new Promise(() => undefined) },
    })
    const raced = await Promise.race([
      channel.send(sendInput()),
      new Promise((r) => setTimeout(() => r('still waiting'), 500)),
    ])
    expect(raced).toMatchObject({ ok: false, retryable: true })
    expect((raced as Channel.SendResult).error).toContain('did not answer')
  })

  it('retries a transient failure rather than dropping the only copy of a link', async () => {
    let attempts = 0
    const channel = new AuthSmtpChannel({
      from: 'noreply@app.test',
      templates: emailTemplate,
      transporter: {
        sendMail: async () => {
          attempts++
          if (attempts < 3) throw new Error('temporary')
          return { messageId: 'x' }
        },
      },
    })
    expect((await channel.send(sendInput())).ok).toBe(true)
    expect(attempts).toBe(3)
  })

  it('sends exactly once when the caller says so', async () => {
    let attempts = 0
    const channel = new AuthSmtpChannel({
      from: 'noreply@app.test',
      retries: 0,
      templates: emailTemplate,
      transporter: {
        sendMail: async () => {
          attempts++
          throw new Error('temporary')
        },
      },
    })
    await channel.send(sendInput())
    expect(attempts).toBe(1)
  })
})

describe('who the recipient is', () => {
  it('the email channels read profile.email and the sms channel reads profile.phone', async () => {
    const { channels, sent } = buildAll()
    await channels.smtp.send(sendInput())
    await channels.twilio.send(sendInput())

    expect(sent.smtp?.[0]).toMatchObject({ to: 'user@app.test' })
    expect(sent.twilio?.[0]).toMatchObject({ to: '+15550100' })
  })

  it('refuses a recipient that is not an address or an E.164 number', async () => {
    const { channels, sent } = buildAll()
    expect((await channels.smtp.send(sendInput({ identity: identity({ email: 'not an address' }) }))).ok).toBe(false)
    expect((await channels.twilio.send(sendInput({ identity: identity({ phone: 'call me maybe' }) }))).ok).toBe(false)
    expect(sent.smtp).toBeUndefined()
    expect(sent.twilio).toBeUndefined()
  })

  it('refuses a recipient carrying CR LF before it can become a second header', async () => {
    const { channels, sent } = buildAll()
    // A single @ and no separator character, so the only rule that can refuse this is the one that
    // rejects the CR LF itself.
    const result = await channels.smtp.send(sendInput({ identity: identity({ email: 'a@b.test\r\nBcc' }) }))
    expect(result.ok).toBe(false)
    expect(sent.smtp).toBeUndefined()
  })

  it('refuses a recipient past the length SMTP allows', async () => {
    // RFC 5321 caps a forward-path at 256 octets and a domain at 255.
    const { channels, sent } = buildAll()
    await channels.smtp.send(sendInput({ identity: identity({ email: `${'a'.repeat(10_000)}@app.test` }) }))
    expect(sent.smtp).toBeUndefined()
    // A local part inside the total cap but over the 64 allowed is refused too.
    await channels.smtp.send(sendInput({ identity: identity({ email: `${'a'.repeat(100)}@app.test` }) }))
    expect(sent.smtp).toBeUndefined()
  })

  it('refuses a comma-separated list rather than letting the provider decide to split it', async () => {
    const { channels, sent } = buildAll()
    // One @ and no space, so every other rule passes this and only the separator rule can refuse it.
    // With a second @ or a space after the comma it is refused either way and proves nothing.
    expect((await channels.resend.send(sendInput({ identity: identity({ email: 'a@b.test,victim' }) }))).ok).toBe(false)
    // The quoting and routing characters go the same way, for the same reason.
    for (const email of ['a@b<c.test', 'a@b;c.test', 'a@b"c.test', 'a@b(c.test', 'a@b[c].test', 'a@b\\c.test']) {
      expect((await channels.resend.send(sendInput({ identity: identity({ email }) }))).ok).toBe(false)
    }
    expect(sent.resend).toBeUndefined()
  })

  it('still delivers to an ordinary address, including a non-ascii one', async () => {
    const { channels, sent } = buildAll()
    expect((await channels.smtp.send(sendInput({ identity: identity({ email: 'user@app.test' }) }))).ok).toBe(true)
    // Left alone rather than refused, so an SMTPUTF8 deployment keeps working.
    expect((await channels.smtp.send(sendInput({ identity: identity({ email: 'usuario@ejemplo.test' }) }))).ok).toBe(
      true,
    )
    expect(sent.smtp).toHaveLength(2)
  })

  it('a non-string recipient is treated as absent rather than coerced', async () => {
    const { channels } = buildAll()
    for (const email of [42, null, {}, ['a@b.test']]) {
      expect((await channels.smtp.send(sendInput({ identity: identity({ email }) }))).ok).toBe(false)
    }
  })
})

describe('how much can go out in one call', () => {
  it('caps the sms body, which is billed per segment', async () => {
    // A resolver interpolating an attacker-influenced variable used to turn one send into thousands
    // of billed segments.
    const channel = new AuthTwilioChannel({
      client: {
        messages: {
          create: async (opts) => {
            expect(opts.body).toHaveLength(1600)
            return { sid: 'x' }
          },
        },
      },
      from: '+15550199',
      templates: () => ({ body: 'x'.repeat(500_000) }),
    })
    expect((await channel.send(sendInput())).ok).toBe(true)
  })

  it('caps an email subject at the length a header line allows', async () => {
    const { sent } = buildAll()
    const channel = new AuthSmtpChannel({
      from: 'noreply@app.test',
      templates: () => ({ subject: 'S'.repeat(50_000), text: 'hi' }),
      transporter: {
        sendMail: async (opts) => {
          sent.smtp = [opts]
          return { messageId: 'x' }
        },
      },
    })
    await channel.send(sendInput())
    expect((sent.smtp?.[0] as { subject: string }).subject).toHaveLength(998)
  })

  it('folds CR LF out of a subject before it can carry a second header', async () => {
    let seen: { subject: string } | undefined
    const channel = new AuthSmtpChannel({
      from: 'noreply@app.test',
      templates: () => ({ subject: 'Sign in\r\nBcc: victim@corp.example', text: 'hi' }),
      transporter: {
        sendMail: async (opts) => {
          seen = opts
          return { messageId: 'x' }
        },
      },
    })
    await channel.send(sendInput())
    expect(seen?.subject).not.toContain('\r')
    expect(seen?.subject).not.toContain('\n')
    // Folded rather than dropped: a subject is cosmetic and the mail still has to go.
    expect(seen?.subject).toBe('Sign in  Bcc: victim@corp.example')
  })

  it('refuses a resolver whose output is the wrong shape, before the network round trip', async () => {
    let seen: Record<string, unknown> | undefined
    const transporter = {
      sendMail: async (opts: Record<string, unknown>) => {
        seen = opts
        return { messageId: 'x' }
      },
    }
    const make = (templates: () => never) =>
      new AuthSmtpChannel({ from: 'noreply@app.test', templates, transporter: transporter as never })

    // No subject at all, and a subject with no body: both are wiring faults that used to surface as
    // a provider rejection one round trip later.
    expect((await make((() => ({})) as never).send(sendInput())).ok).toBe(false)
    expect((await make((() => ({ subject: 'x' })) as never).send(sendInput())).ok).toBe(false)
    expect((await make((() => ({ subject: 42, text: 'hi' })) as never).send(sendInput())).ok).toBe(false)
    expect(seen).toBeUndefined()
  })

  it('spends a budget per send, because toll fraud against an SMS route is a loop over this call', async () => {
    const seen: unknown[] = []
    const channel = new AuthTwilioChannel({
      client: {
        messages: {
          create: async (opts) => {
            seen.push(opts)
            return { sid: 'x' }
          },
        },
      },
      from: '+15550199',
      limiter: new MemoryLimiter({ max: 3 }),
      templates: () => ({ body: 'your code is 123456' }),
    })
    const results = []
    for (let i = 0; i < 5; i++) results.push(await channel.send(sendInput()))
    expect(seen).toHaveLength(3)
    expect(results[4]).toMatchObject({ ok: false, retryable: true })
    expect(results[4]?.error).toContain('budget exhausted')
  })

  it('takes a caller-supplied bucket, for an app that knows who is asking', async () => {
    const keys: string[] = []
    const channel = new AuthTwilioChannel({
      client: { messages: { create: async () => ({ sid: 'x' }) } },
      from: '+15550199',
      limiter: {
        consume: async (key) => {
          keys.push(key)
          return { ok: true, remaining: 1, resetAt: new Date() }
        },
        reset: async () => undefined,
      },
      limiterKey: (input) => `sms:${input.identity.id}`,
      templates: () => ({ body: 'your code is 123456' }),
    })
    await channel.send(sendInput())
    expect(keys).toEqual(['sms:ident-1'])
  })
})

describe('the development channels', () => {
  it('keeps the credential out of the line, which is where the magic link lives', async () => {
    // `vars` carries the signed link or the one-time code, and the whole object went into the log
    // line, so anyone reading stdout could sign in as that user.
    const lines: string[] = []
    const channel = new AuthConsoleChannel({ sink: (line) => lines.push(line) })
    await channel.send(sendInput({ vars: { code: '482913', token: 'SECRET-TOKEN', url: 'https://app.test/magic' } }))

    expect(lines[0]).not.toContain('SECRET-TOKEN')
    expect(lines[0]).toContain('[redacted]')
    // What is not a credential still reaches the line, or the channel is useless for development.
    expect(lines[0]).toContain('https://app.test/magic')
  })

  it('the console channel keeps the profile out of the line, as documented', async () => {
    const lines: string[] = []
    const channel = new AuthConsoleChannel({ sink: (line) => lines.push(line) })
    await channel.send(sendInput({ identity: identity({ email: 'pii@corp.example', phone: '+15550100' }) }))

    expect(lines[0]).toContain('ident-1')
    expect(lines[0]).not.toContain('pii@corp.example')
  })

  it('refuses to be constructed under NODE_ENV=production, as the null captcha verifier does', () => {
    const before = process.env.NODE_ENV
    process.env.NODE_ENV = 'production'
    try {
      expect(() => new AuthNoopChannel()).toThrow(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))
      expect(() => new AuthConsoleChannel({ sink: () => undefined })).toThrow(
        expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
      )
      // The escape hatch is explicit, so a deployment that means it can still say so.
      expect(() => new AuthNoopChannel({ development: true })).not.toThrow()
    } finally {
      process.env.NODE_ENV = before
    }
  })

  it('the noop channel reports no message id for a message that was never sent', async () => {
    // A caller storing the id for support diagnostics was recording a delivery that did not happen.
    const result = await new AuthNoopChannel().send(sendInput())
    expect(result.ok).toBe(true)
    expect(result.providerMessageId).toBeUndefined()
  })

  it('both take their kind from config, so an email channel can claim to be sms', () => {
    expect(new AuthConsoleChannel({ kind: 'sms' }).kind).toBe('sms')
    expect(new AuthNoopChannel({ kind: 'webpush' }).kind).toBe('webpush')
  })
})

describe('web push, which has a payload ceiling the others do not', () => {
  const build = (send: (sub: unknown, payload: string) => Promise<unknown>) =>
    new AuthWebPushChannel({
      module: { sendNotification: send, setVapidDetails: vi.fn() } as never,
      privateKey: 'cHJpdmF0ZS1rZXk',
      publicKey: 'cHVibGljLWtleQ',
      subject: 'mailto:ops@app.test',
      templates: () => ({ payload: JSON.stringify({ body: 'hi', title: 'Sign in' }) }),
    })

  const withSubscription = (over: Record<string, unknown> = {}) =>
    sendInput({
      identity: identity({
        pushSubscription: { endpoint: 'https://push.example/abc', keys: { auth: 'a', p256dh: 'p' }, ...over },
      }),
    })

  it('refuses an identity with no subscription', async () => {
    const channel = build(async () => ({}))
    expect(await channel.send(sendInput())).toMatchObject({ ok: false })
  })

  it('sends the rendered payload to the subscription endpoint', async () => {
    const seen: Array<{ payload: string; sub: unknown }> = []
    const channel = build(async (sub, payload) => {
      seen.push({ payload, sub })
      return {}
    })
    expect((await channel.send(withSubscription())).ok).toBe(true)
    expect(seen[0]?.payload).toContain('Sign in')
  })

  it('refuses a payload over the four kilobyte ceiling before the push service does', async () => {
    // RFC 8291 caps an encrypted push payload at 4096 octets; an over-long template used to fail
    // at the push service rather than here.
    let called = false
    const channel = new AuthWebPushChannel({
      module: {
        sendNotification: async () => {
          called = true
          return {}
        },
        setVapidDetails: vi.fn(),
      } as never,
      privateKey: 'cHJpdmF0ZS1rZXk',
      publicKey: 'cHVibGljLWtleQ',
      subject: 'mailto:ops@app.test',
      templates: () => ({ payload: JSON.stringify({ body: 'x'.repeat(20_000), title: 'Sign in' }) }),
    })
    expect(await channel.send(withSubscription())).toMatchObject({ ok: false, retryable: false })
    expect(called).toBe(false)
  })

  it('checks the subscription endpoint, which is a URL off a user-editable profile field', async () => {
    // The same shape the webhook deliverer guards against for its own outbound calls.
    const seen: unknown[] = []
    const channel = build(async (sub) => {
      seen.push(sub)
      return {}
    })
    for (const endpoint of ['http://127.0.0.1:8080/internal', 'https://169.254.169.254/latest/meta-data']) {
      expect(await channel.send(withSubscription({ endpoint }))).toMatchObject({ ok: false, retryable: false })
    }
    expect(seen).toHaveLength(0)
  })
})
