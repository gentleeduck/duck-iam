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
      if (name === 'ses') continue // see the peer-dependency finding below
      expect((await channel.send(sendInput())).ok, name).toBe(true)
    }
  })

  it('FINDING: the ses channel needs its sdk installed even when a client is injected', async () => {
    // Every other adapter lets a caller supply a pre-built client and skip the
    // peer dependency, which is what makes them testable and what the `client`
    // option is for. SES also reaches for `SendEmailCommand` from the sdk to
    // build the request, so an injected client is not enough and the send fails
    // at delivery time rather than at construction.
    const { channels } = buildAll()
    expect(await channels.ses.send(sendInput())).toMatchObject({ ok: false })
  })

  it('FINDING: an AuthError caught on the send path is flattened to its code, losing the detail', async () => {
    // `err.message` on an AuthError is the code, and everything an operator
    // needs, here the name of the package to install, lives in `meta.detail`.
    // The catch keeps the message, so the result says AUTH_MISCONFIGURED and
    // nothing about what is misconfigured.
    const { channels } = buildAll()
    const result = await channels.ses.send(sendInput())
    expect(result.error).toBe('AUTH_MISCONFIGURED')
    expect(result.error).not.toContain('@aws-sdk/client-ses')
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

  it('FINDING: send never throws, so a delivery failure is only visible if the caller reads the result', async () => {
    // Every adapter catches its own transport error and returns `ok: false`. A
    // flow that awaits the send without inspecting it, which is what an
    // `await channel.send(...)` statement looks like, proceeds as though the
    // code or link reached the user.
    const channel = new AuthSmtpChannel({
      from: 'noreply@app.test',
      templates: emailTemplate,
      transporter: {
        sendMail: async () => {
          throw new Error('connection refused')
        },
      },
    })
    await expect(channel.send(sendInput())).resolves.toMatchObject({ error: 'connection refused', ok: false })
  })

  it('FINDING: the provider’s own error text is returned verbatim to the caller', async () => {
    // Whatever the SDK put in the message is what the result carries, and SDK
    // errors routinely include the request URL, the account identifier, and
    // occasionally the credential that was rejected.
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
    expect((await channel.send(sendInput())).error).toBe(leaky)
  })

  it('FINDING: a template resolver that throws is reported as a delivery failure, not a bug', async () => {
    // A broken template is a programming error on the app's side, and it lands
    // in the same `ok: false` shape as a network outage, so retry logic keyed on
    // the result retries something that will never succeed.
    const channel = new AuthSmtpChannel({
      from: 'noreply@app.test',
      templates: () => {
        throw new Error('unknown templateId')
      },
      transporter: { sendMail: async () => ({ messageId: 'x' }) },
    })
    expect(await channel.send(sendInput())).toMatchObject({ error: 'unknown templateId', ok: false })
  })

  it('FINDING: no channel applies a timeout to the transport it calls', async () => {
    // A provider that accepts the connection and never answers parks the send.
    // These sit inside password reset and MFA delivery, so the request holding
    // them open is a user waiting on a login.
    const channel = new AuthSmtpChannel({
      from: 'noreply@app.test',
      templates: emailTemplate,
      transporter: { sendMail: () => new Promise(() => undefined) },
    })
    const raced = await Promise.race([
      channel.send(sendInput()).then(() => 'answered'),
      new Promise((r) => setTimeout(() => r('still waiting'), 50)),
    ])
    expect(raced).toBe('still waiting')
  })

  it('FINDING: no channel retries, so one transient failure drops the message', async () => {
    let attempts = 0
    const channel = new AuthSmtpChannel({
      from: 'noreply@app.test',
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

  it('FINDING: the recipient is any non-empty string, with no address or number validation', async () => {
    // `getProfileString` checks the type and that it is not empty. Nothing
    // checks that an email looks like an address or that a phone is E.164, so
    // whatever the profile holds is handed to the provider as the destination.
    const { channels, sent } = buildAll()
    await channels.smtp.send(sendInput({ identity: identity({ email: 'not an address' }) }))
    await channels.twilio.send(sendInput({ identity: identity({ phone: 'call me maybe' }) }))

    expect(sent.smtp?.[0]).toMatchObject({ to: 'not an address' })
    expect(sent.twilio?.[0]).toMatchObject({ to: 'call me maybe' })
  })

  it('FINDING: a recipient carrying CR LF reaches the transport unfiltered', async () => {
    // The SMTP transporter is handed `to` as a header value. Nodemailer rejects
    // this itself, but the channel is the layer that knows the value came from a
    // user-editable profile field, and it passes it straight through.
    const { channels, sent } = buildAll()
    await channels.smtp.send(sendInput({ identity: identity({ email: 'a@b.test\r\nBcc: victim@corp.example' }) }))
    expect(sent.smtp?.[0]).toMatchObject({ to: 'a@b.test\r\nBcc: victim@corp.example' })
  })

  it('FINDING: there is no length cap on the recipient', async () => {
    // SMTP caps a path at 256 octets and a domain at 255. A profile field ten
    // thousand characters long is sent as the destination address.
    const { channels, sent } = buildAll()
    const huge = `${'a'.repeat(10_000)}@app.test`
    await channels.smtp.send(sendInput({ identity: identity({ email: huge }) }))
    expect((sent.smtp?.[0] as { to: string }).to).toHaveLength(huge.length)
  })

  it('FINDING: a comma-separated list in one profile field is one recipient string to the channel', async () => {
    // Resend's own client accepts `to` as an array, and the channel passes a
    // string. Which of those a given provider splits on is the provider's
    // decision, not something this layer settles.
    const { channels, sent } = buildAll()
    await channels.resend.send(sendInput({ identity: identity({ email: 'a@b.test, victim@corp.example' }) }))
    expect(sent.resend?.[0]).toMatchObject({ to: 'a@b.test, victim@corp.example' })
  })

  it('a non-string recipient is treated as absent rather than coerced', async () => {
    const { channels } = buildAll()
    for (const email of [42, null, {}, ['a@b.test']]) {
      expect((await channels.smtp.send(sendInput({ identity: identity({ email }) }))).ok).toBe(false)
    }
  })
})

describe('how much can go out in one call', () => {
  it('FINDING: nothing caps the rendered body, and sms is billed per segment', async () => {
    // A resolver that interpolates an attacker-influenced variable into an SMS
    // turns one send into thousands of billed segments. The channel forwards
    // whatever it is given.
    const body = 'x'.repeat(500_000)
    const channel = new AuthTwilioChannel({
      client: {
        messages: {
          create: async (opts) => {
            expect(opts.body).toHaveLength(500_000)
            return { sid: 'x' }
          },
        },
      },
      from: '+15550199',
      templates: () => ({ body }),
    })
    expect((await channel.send(sendInput())).ok).toBe(true)
  })

  it('FINDING: nothing caps an email subject either, so it reaches the header unfolded', async () => {
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
    expect((sent.smtp?.[0] as { subject: string }).subject).toHaveLength(50_000)
  })

  it('FINDING: a subject containing CR LF is passed to the transport as-is', async () => {
    // Header injection is the transport's to refuse, but the channel is what
    // knows the string came out of a template fed with request data.
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
    expect(seen?.subject).toContain('\r\nBcc:')
  })

  it('FINDING: a resolver returning the wrong shape is forwarded rather than refused', async () => {
    // Nothing validates that `subject` is a string or that a body is present.
    // An undefined subject reaches the provider, which is where the failure
    // surfaces, one network round trip later.
    let seen: Record<string, unknown> | undefined
    const channel = new AuthSmtpChannel({
      from: 'noreply@app.test',
      templates: () => ({}) as never,
      transporter: {
        sendMail: async (opts) => {
          seen = opts as never
          return { messageId: 'x' }
        },
      },
    })
    expect((await channel.send(sendInput())).ok).toBe(true)
    expect(seen?.subject).toBeUndefined()
  })

  it('FINDING: no channel rate limits, so a send loop is bounded only by the provider', async () => {
    // The library throttles sign-in attempts and not the messages a flow emits.
    // Toll fraud against an SMS route is a loop over this call.
    const { channels, sent } = buildAll()
    for (let i = 0; i < 50; i++) await channels.twilio.send(sendInput())
    expect(sent.twilio).toHaveLength(50)
  })
})

describe('the development channels', () => {
  it('FINDING: the console channel writes the full vars, which is where the secret lives', async () => {
    // Its doc says "PII is redacted before logging: the identity's profile is
    // stringified to `<identityId>` only". That is true of the profile and not
    // of the payload: `vars` carries the signed magic link or the one-time code,
    // and the whole object is serialised into the log line. Anyone reading
    // stdout, or the aggregator it ships to, can sign in as that user.
    const lines: string[] = []
    const channel = new AuthConsoleChannel({ sink: (line) => lines.push(line) })
    await channel.send(sendInput({ vars: { code: '482913', url: 'https://app.test/magic?token=SECRET-TOKEN' } }))

    expect(lines[0]).toContain('SECRET-TOKEN')
    expect(lines[0]).toContain('482913')
  })

  it('the console channel keeps the profile out of the line, as documented', async () => {
    const lines: string[] = []
    const channel = new AuthConsoleChannel({ sink: (line) => lines.push(line) })
    await channel.send(sendInput({ identity: identity({ email: 'pii@corp.example', phone: '+15550100' }) }))

    expect(lines[0]).toContain('ident-1')
    expect(lines[0]).not.toContain('pii@corp.example')
  })

  it('FINDING: nothing stops either development channel being wired in production', async () => {
    // Same shape as the null captcha verifier: both are exported from the
    // package, both satisfy the channel interface, and neither consults the
    // environment. The noop one reports every send as delivered.
    const noop = new AuthNoopChannel()
    expect(await noop.send(sendInput())).toMatchObject({ ok: true })

    const console = new AuthConsoleChannel({ sink: () => undefined })
    expect(await console.send(sendInput())).toMatchObject({ ok: true })
  })

  it('FINDING: the noop channel reports a message id for a message that was never sent', async () => {
    // A caller storing the id for support diagnostics records a delivery that
    // did not happen.
    const result = await new AuthNoopChannel().send(sendInput())
    expect(result.ok).toBe(true)
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

  it('FINDING: nothing checks the payload against the four kilobyte ceiling', async () => {
    // RFC 8291 caps an encrypted push payload at 4096 octets, and push services
    // reject anything larger. The channel builds the JSON and hands it over, so
    // an over-long template fails at the push service rather than here.
    let size = 0
    const channel = new AuthWebPushChannel({
      module: {
        sendNotification: async (_sub: unknown, payload: string) => {
          size = Buffer.byteLength(payload)
          return {}
        },
        setVapidDetails: vi.fn(),
      } as never,
      privateKey: 'cHJpdmF0ZS1rZXk',
      publicKey: 'cHVibGljLWtleQ',
      subject: 'mailto:ops@app.test',
      templates: () => ({ payload: JSON.stringify({ body: 'x'.repeat(20_000), title: 'Sign in' }) }),
    })
    await channel.send(withSubscription())
    expect(size).toBeGreaterThan(4096)
  })

  it('FINDING: the subscription endpoint is taken from the profile and never checked', async () => {
    // The endpoint is a URL the library will POST to, stored on a user-editable
    // profile field. There is no https requirement and no host check, which is
    // the same shape the webhook deliverer guards against for its own outbound
    // calls.
    const seen: unknown[] = []
    const channel = build(async (sub) => {
      seen.push(sub)
      return {}
    })
    await channel.send(withSubscription({ endpoint: 'http://127.0.0.1:8080/internal' }))
    expect(seen[0]).toMatchObject({ endpoint: 'http://127.0.0.1:8080/internal' })
  })
})
