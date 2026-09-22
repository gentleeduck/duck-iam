/**
 * `recovery.mfa.escalated` was declared, listed in `AUDITED_EVENTS`, allowed through the webhook
 * filter — and emitted by nothing. Spending a backup code is a second factor satisfied without the
 * factor, and the only trace it left was `backup-code` on the rotated session's own factor list.
 */

import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import type { Events } from '~/core/events'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { mfaProvider, totpAt } from '~/providers/mfa'

type MyProfile = { username: string; email: string }

let seq = 0

async function enrolled(): Promise<{
  auth: AuthEngine<MyProfile>
  adapter: MemoryAdapter<MyProfile>
  identityId: string
  codes: string[]
  escalations: Events.EventMap['recovery.mfa.escalated'][]
}> {
  const adapter = new MemoryAdapter<MyProfile>()
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://x',
    limiter: new MemoryLimiter({ max: 99, windowMs: 60_000 }),
    providers: [mfaProvider()],
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid', secure: false }),
  })
  const escalations: Events.EventMap['recovery.mfa.escalated'][] = []
  auth.events.on('recovery.mfa.escalated', (p) => {
    escalations.push(p)
  })
  const email = `a${seq++}@x.com`
  const ident = await auth.identities.create({ profile: { email, username: email } })
  const codes = await auth.mfa.regenerateBackupCodes(ident.id)
  return { adapter, auth, codes, escalations, identityId: ident.id }
}

describe('spending a backup code reaches the bus', () => {
  it('emits recovery.mfa.escalated naming the identity and the code that was spent', async () => {
    const { adapter, auth, codes, escalations, identityId } = await enrolled()
    const before = await adapter.credentials.listByIdentity(identityId, 'recovery', {})

    expect(await auth.mfa.verifyBackupCode(identityId, codes[0] as string)).toBe(true)

    expect(escalations).toHaveLength(1)
    expect(escalations[0]?.identityId).toBe(identityId)
    expect(before.map((r) => r.id)).toContain(escalations[0]?.credentialId)
  })

  it('names a row already burnt and revoked at the moment it fires, not merely by the time the call returns', async () => {
    // Read inside the handler, because the bus awaits it: a subscriber that acts on this event sees the
    // row as it stands here. Asserting after `verifyBackupCode` resolves would pass just as well with the
    // emit moved above the claim, which is the ordering that would hand a live code to a webhook.
    const { adapter, auth, codes, identityId } = await enrolled()
    const before = await adapter.credentials.listByIdentity(identityId, 'recovery', {})
    const secrets = new Map(before.map((r) => [r.id, r.secret]))
    let atEmit: { credentialId: string; revokedAt: unknown; secret: string } | undefined
    auth.events.on('recovery.mfa.escalated', async (p) => {
      const row = (await adapter.credentials.listByIdentity(identityId, 'recovery', {})).find(
        (r) => r.id === p.credentialId,
      )
      if (row) atEmit = { credentialId: p.credentialId, revokedAt: row.revokedAt, secret: row.secret }
    })

    await auth.mfa.verifyBackupCode(identityId, codes[0] as string)

    expect(atEmit).toBeDefined()
    expect(atEmit?.revokedAt).not.toBeNull()
    expect(atEmit?.secret).not.toBe(secrets.get(atEmit?.credentialId as string))
  })

  it('stays silent on a code that matches nothing', async () => {
    const { auth, escalations, identityId } = await enrolled()

    expect(await auth.mfa.verifyBackupCode(identityId, 'nope-nope')).toBe(false)

    expect(escalations).toEqual([])
  })

  it('emits once when two verifications race for one code, not once per attempt', async () => {
    const { auth, codes, escalations, identityId } = await enrolled()
    const code = codes[0] as string

    const both = await Promise.all([
      auth.mfa.verifyBackupCode(identityId, code),
      auth.mfa.verifyBackupCode(identityId, code),
    ])

    expect(both.filter(Boolean)).toHaveLength(1)
    expect(escalations).toHaveLength(1)
  })

  it('carries through completeStepUp, which is the path a user without their device takes', async () => {
    const { auth, codes, escalations, identityId } = await enrolled()
    const { sid } = await auth.sessions.create({
      identityId,
      kind: 'user',
      aal: 1,
      factors: [{ method: 'password', completedAt: new Date() }],
    })

    const stepped = await auth.flows.completeStepUp({
      code: codes[0] as string,
      currentSid: sid,
      method: 'backup-code',
    })

    expect(stepped.session.aal).toBe(2)
    expect(escalations).toHaveLength(1)
    expect(escalations[0]?.identityId).toBe(identityId)
  })

  it('does not fire for a TOTP step-up, which satisfied the factor rather than recovering from it', async () => {
    const { auth, escalations, identityId } = await enrolled()
    const challenge = await auth.mfa.beginTotpEnrollment(identityId, 'a@x.com')
    const step = Math.floor(Date.now() / 1000 / 30)
    await auth.mfa.confirmTotpEnrollment(identityId, totpAt(challenge.secret, step))
    const { sid } = await auth.sessions.create({
      identityId,
      kind: 'user',
      aal: 1,
      factors: [{ method: 'password', completedAt: new Date() }],
    })

    await auth.flows.completeStepUp({ code: totpAt(challenge.secret, step + 1), currentSid: sid, method: 'totp' })

    expect(escalations).toEqual([])
  })
})
