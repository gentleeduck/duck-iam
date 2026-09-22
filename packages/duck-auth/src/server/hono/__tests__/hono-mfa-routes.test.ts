/** The MFA routes `mountHono` registers, exercised through the mount rather than through the facet. */

import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { DEFAULT_MFA_CONFIG, mfaProvider, totpAt } from '~/providers/mfa'
import { passwords, ScryptHasher } from '~/providers/passwords'
import type { MountHono } from '../hono.types'
import { mountHono } from '../index'

type MyProfile = { username: string; email: string }

const MAX_ATTEMPTS = 5

/** Read at the moment it is used: a step index captured earlier falls outside the drift window once the
 *  clock crosses a thirty-second boundary, which fails the test on timing rather than on the product. */
const nowStep = () => Math.floor(Date.now() / 1000 / 30)

function buildAuth() {
  const adapter = new MemoryAdapter<MyProfile>()
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://x',
    limiter: new MemoryLimiter({ max: MAX_ATTEMPTS, windowMs: 60_000 }),
    providers: [passwords<MyProfile>({ hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) }), mfaProvider()],
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid', secure: false }),
  })
  return auth
}

/** Mount against a recorder rather than a real Hono, which this package does not depend on. */
function mountAndTake(auth: AuthEngine<MyProfile>, path: string) {
  const registered: Record<string, (c: MountHono.HonoCtx) => Response | Promise<Response>> = {}
  const app: MountHono.App = {
    get(p, h) {
      registered[p] = h
    },
    post(p, h) {
      registered[p] = h
    },
  }
  mountHono(app, auth)
  const handler = registered[path]
  if (!handler) throw new Error(`no handler registered at ${path}`)
  return handler
}

/** A request carrying the session cookie and a matching double-submit token, as a browser would. */
function post(url: string, creds: { sid: string; csrfToken: string }, body: unknown): MountHono.HonoCtx {
  const headers = {
    cookie: `duck-sid=${creds.sid}; duck-csrf=${creds.csrfToken}`,
    'content-type': 'application/json',
    'x-csrf-token': creds.csrfToken,
  }
  const raw = new Request(`https://x${url}`, { body: JSON.stringify(body), headers, method: 'POST' })
  return {
    req: {
      header: (name?: string) => (name === undefined ? headers : (raw.headers.get(name) ?? undefined)),
      json: async () => body,
      method: 'POST',
      param: () => undefined,
      raw,
      url: `https://x${url}`,
    },
  } as unknown as MountHono.HonoCtx
}

/** An identity with a confirmed TOTP factor, plus a session at whatever AAL the caller asks for. */
async function enrolled(auth: AuthEngine<MyProfile>, aal: 1 | 2) {
  const ident = await auth.identities.create({ profile: { email: 'a@x.com', username: 'a@x.com' } })
  const challenge = await auth.mfa.beginTotpEnrollment(ident.id, 'a@x.com')
  const step = nowStep()
  const confirmed = await auth.mfa.confirmTotpEnrollment(ident.id, totpAt(challenge.secret, step))
  if (!confirmed.ok || !confirmed.backupCodes[0]) throw new Error('enrollment produced no backup codes')
  const backupCode = confirmed.backupCodes[0]
  const created = await auth.sessions.create({
    aal,
    factors: [{ completedAt: new Date(), method: 'password' }],
    identityId: ident.id,
    kind: 'user',
  })
  return {
    backupCode,
    csrfToken: created.csrfToken,
    identityId: ident.id,
    secret: challenge.secret,
    sid: created.sid,
    step,
  }
}

describe('the MFA routes mountHono registers', () => {
  it('refuses to remove the second factor for a session that only proved a password', async () => {
    const auth = buildAuth()
    const handler = mountAndTake(auth, '/auth/mfa/totp/remove')
    const who = await enrolled(auth, 1)

    const res = await handler(post('/auth/mfa/totp/remove', who, {}))

    expect(res.status).toBe(401)
    expect(await auth.mfa.hasTotp(who.identityId)).toBe(true)
  })

  it('still lets a stepped-up session remove it, which is the supported way', async () => {
    const auth = buildAuth()
    const handler = mountAndTake(auth, '/auth/mfa/totp/remove')
    const who = await enrolled(auth, 2)

    const res = await handler(post('/auth/mfa/totp/remove', who, {}))

    expect(res.status).toBe(200)
    expect(await auth.mfa.hasTotp(who.identityId)).toBe(false)
  })

  it('refuses to start a fresh enrollment over the second factor for a password-only session', async () => {
    const auth = buildAuth()
    const handler = mountAndTake(auth, '/auth/mfa/totp/begin')
    const who = await enrolled(auth, 1)

    const res = await handler(post('/auth/mfa/totp/begin', who, { label: 'a@x.com' }))

    // The route `/remove` is guarded against, reached through the one that asks for nothing: starting an
    // enrollment used to delete the confirmed row first, handing the caller a secret of their own.
    expect(res.status).toBe(401)
    expect(await auth.mfa.hasTotp(who.identityId)).toBe(true)
    expect(await auth.mfa.verifyTotp(who.identityId, totpAt(who.secret, nowStep() + 1))).toBe(true)
  })

  it('still lets a stepped-up session remove and re-enroll, which is the supported way', async () => {
    const auth = buildAuth()
    const remove = mountAndTake(auth, '/auth/mfa/totp/remove')
    const begin = mountAndTake(auth, '/auth/mfa/totp/begin')
    const who = await enrolled(auth, 2)

    expect((await remove(post('/auth/mfa/totp/remove', who, {}))).status).toBe(200)
    const res = await begin(post('/auth/mfa/totp/begin', who, { label: 'a@x.com' }))

    expect(res.status).toBe(200)
    expect((await res.json()).secret).not.toBe(who.secret)
  })

  it('bounds the verify route, which answers ok:false as an oracle for as long as it is asked', async () => {
    const auth = buildAuth()
    const handler = mountAndTake(auth, '/auth/mfa/totp/verify')
    const who = await enrolled(auth, 1)

    const statuses: number[] = []
    for (let i = 0; i < MAX_ATTEMPTS + 3; i++) {
      const res = await handler(post('/auth/mfa/totp/verify', who, { code: String(100000 + i) }))
      statuses.push(res.status)
    }

    expect(statuses).toContain(429)
  })

  it('shares one budget with completeStepUp, so a grinder cannot buy a second by switching routes', async () => {
    const auth = buildAuth()
    const handler = mountAndTake(auth, '/auth/mfa/totp/verify')
    const who = await enrolled(auth, 1)

    for (let i = 0; i < MAX_ATTEMPTS; i++) {
      await handler(post('/auth/mfa/totp/verify', who, { code: String(100000 + i) }))
    }

    // The right code, through the other door. Spent is spent.
    await expect(
      auth.flows.completeStepUp({ code: totpAt(who.secret, who.step), currentSid: who.sid, method: 'totp' }),
    ).rejects.toMatchObject({ code: 'AUTH_RATE_LIMITED' })
  })

  it('refuses to regenerate the backup codes for a session that only proved a password', async () => {
    const auth = buildAuth()
    const handler = mountAndTake(auth, '/auth/mfa/backup-codes/regenerate')
    const who = await enrolled(auth, 1)

    const res = await handler(post('/auth/mfa/backup-codes/regenerate', who, {}))

    // A 200 puts ten working second factors in the response body, which is the whole gate: any of them
    // takes the caller who has only the password straight to AAL2.
    expect(res.status).toBe(401)
    expect(await res.json()).not.toHaveProperty('codes')
  })

  it('leaves the enrolled codes spendable, so a refused regenerate locks nobody out', async () => {
    const auth = buildAuth()
    const handler = mountAndTake(auth, '/auth/mfa/backup-codes/regenerate')
    const who = await enrolled(auth, 1)

    await handler(post('/auth/mfa/backup-codes/regenerate', who, {}))

    await expect(
      auth.flows.completeStepUp({ code: who.backupCode, currentSid: who.sid, method: 'backup-code' }),
    ).resolves.toMatchObject({ session: { aal: 2 } })
  })

  it('still regenerates them for a stepped-up session, replacing the old set', async () => {
    const auth = buildAuth()
    const handler = mountAndTake(auth, '/auth/mfa/backup-codes/regenerate')
    const who = await enrolled(auth, 2)

    const res = await handler(post('/auth/mfa/backup-codes/regenerate', who, {}))

    expect(res.status).toBe(200)
    const body: { codes?: string[] } = await res.json()
    expect(body.codes).toHaveLength(DEFAULT_MFA_CONFIG.backupCodeCount)
    await expect(
      auth.flows.completeStepUp({ code: who.backupCode, currentSid: who.sid, method: 'backup-code' }),
    ).rejects.toMatchObject({ code: 'AUTH_INVALID_CREDENTIALS' })
  })
})
