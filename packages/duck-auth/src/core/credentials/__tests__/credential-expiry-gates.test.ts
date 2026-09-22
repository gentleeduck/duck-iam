/**
 * `expiresAt` is a column on every credential row, a documented option on `createApiKey`, and part of the
 * `Credential.Store` contract a host implements, so any kind can carry one. `ApiKeyImpl.verify` refuses an
 * elapsed row exactly as it refuses a revoked one, and `isStandingFactor` - the predicate both lockout
 * guards count with - refuses one for `password`, `passkey` and `api-key` alike.
 *
 * Seven gates read `revokedAt` and nothing else. Measured on the password one: `complete` answered a full
 * `startSession` intent on a lapsed row while `isStandingFactor` on that same row answered `false`, so the
 * engine refused to unlink the account's last provider - on the grounds it would become unreachable -
 * through a password that was at that moment minting sessions.
 *
 * `beginPasskeyRegistration`'s `excludeCredentials` is deliberately not among them: its comment says a
 * revoked passkey is left out of the exclusion list so re-enrolling the authenticator is the way back, and
 * an expired one wants the same treatment.
 */
import { describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { randomToken, sha256, timingSafeEqual } from '~/core/crypto'
import type { Events } from '~/core/events'
import { InMemoryEvents } from '~/core/events'
import type { Identities } from '~/core/identities'
import { MemoryLimiter } from '~/limiters/memory'
import { BackupCodesFacet } from '~/providers/mfa/internal/backup-codes'
import { MfaImpl } from '~/providers/mfa/mfa'
import { passkey } from '~/providers/passkey'
import type { Passkey } from '~/providers/passkey/passkey.types'
import type { Hasher } from '~/providers/passwords/hashers/hashers.types'
import { passwordsImpl } from '~/providers/passwords/passwords'
import { identityInput } from '~/test/store-inputs'
import { isStandingFactor } from '../credentials'
import type { Credential } from '../credentials.types'

interface ProfileShape extends Identities.ProfileMetadataBase {}

const CRYPTO = { authRandomToken: randomToken, authSha256: sha256, authTimingSafeEqual: timingSafeEqual }
const bus = { emit: async () => {}, off: () => {}, on: () => () => {} } as unknown as Events.IBus

/** Reversible and cheap, so no test here pays a KDF's cost. */
const stubHasher: Hasher.Me = {
  id: 'stub',
  hash: async (plaintext: string) => `h:${plaintext}`,
  needsRehash: (encoded: string) => !encoded.startsWith('h:'),
  verify: async (plaintext: string, encoded: string) => encoded === `h:${plaintext}`,
}

let seq = 0
async function identity(adapter: MemoryAdapter<ProfileShape>): Promise<string> {
  const n = seq++
  const row = await adapter.identities.create(
    identityInput({ profile: { email: `a${n}@b.com`, username: `u${n}` }, providers: [] }) as never,
  )
  return row.id
}

/**
 * A row that lapses rather than one born expired: `MemoryAdapter` refuses an `expiresAt` that precedes
 * `createdAt`, which is the only shape a store will ever hold.
 */
async function lapsed(
  credentials: Credential.Store,
  input: Pick<Credential.CreateInput, 'identityId' | 'kind' | 'secret'> & Partial<Credential.CreateInput>,
): Promise<Credential.Me> {
  const row = await credentials.create(
    {
      expiresAt: new Date(Date.now() + 30),
      lastUsedAt: null,
      metadata: null,
      revokedAt: null,
      tenantId: null,
      ...input,
    } as Credential.CreateInput,
    {},
  )
  await new Promise((resolve) => setTimeout(resolve, 50))
  return row
}

function passwordCtx(adapter: MemoryAdapter<ProfileShape>) {
  return {
    baseUrl: 'https://x',
    crypto: CRYPTO,
    events: new InMemoryEvents(),
    limiter: new MemoryLimiter({ max: 50, windowMs: 60_000 }),
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    tenant: {},
  }
}

describe('a password past its expiresAt', () => {
  it('no longer signs in, and the sign-in gate now agrees with isStandingFactor', async () => {
    const adapter = new MemoryAdapter<ProfileShape>()
    const id = await identity(adapter)
    const email = `a${seq - 1}@b.com`
    await lapsed(adapter.credentials, { identityId: id, kind: 'password', secret: 'h:hunter2' })

    const rows = await adapter.credentials.listByIdentity(id, 'password', {})
    expect(rows.map(isStandingFactor)).toEqual([false])
    await expect(
      passwordsImpl({ hasher: stubHasher }).complete(passwordCtx(adapter) as never, { email, password: 'hunter2' }),
    ).rejects.toMatchObject({ code: 'AUTH_INVALID_CREDENTIALS' })
  })

  it('verify answers ok:false, where an unexpired row answers ok:true', async () => {
    const adapter = new MemoryAdapter<ProfileShape>()
    const id = await identity(adapter)
    const provider = passwordsImpl({ hasher: stubHasher })
    await lapsed(adapter.credentials, { identityId: id, kind: 'password', secret: 'h:hunter2' })
    expect(await provider.verify(id, 'hunter2', adapter.credentials)).toEqual({ ok: false })

    const live = await identity(adapter)
    await adapter.credentials.create(
      {
        expiresAt: new Date(Date.now() + 600_000),
        identityId: live,
        kind: 'password',
        lastUsedAt: null,
        metadata: null,
        revokedAt: null,
        secret: 'h:hunter2',
        tenantId: null,
      },
      {},
    )
    expect(await provider.verify(live, 'hunter2', adapter.credentials)).toEqual({ ok: true, needsRehash: false })
  })

  it('is not the row rehash rewrites', async () => {
    const adapter = new MemoryAdapter<ProfileShape>()
    const id = await identity(adapter)
    await lapsed(adapter.credentials, { identityId: id, kind: 'password', secret: 'stale:hunter2' })
    await passwordsImpl({ hasher: stubHasher }).rehash(id, 'hunter2', adapter.credentials)
    const [row] = await adapter.credentials.listByIdentity(id, 'password', {})
    expect(row?.secret).toBe('stale:hunter2')
  })
})

describe('a passkey past its expiresAt', () => {
  const mockWebauthn = (): Passkey.SimpleWebAuthnServerModule =>
    ({
      generateAuthenticationOptions: vi.fn(async (input: { allowCredentials?: unknown }) => ({
        allowCredentials: input.allowCredentials,
        challenge: 'auth-challenge',
      })),
      verifyAuthenticationResponse: vi.fn(async () => ({
        authenticationInfo: { credentialID: 'cred-1', newCounter: 5, userVerified: true },
        verified: true,
      })),
    }) as unknown as Passkey.SimpleWebAuthnServerModule

  const provider = (adapter: MemoryAdapter<ProfileShape>, id: string) =>
    passkey({
      expectedOrigins: 'https://app.test',
      findIdentityByEmail: async () => ({ id }),
      rpID: 'app.test',
      rpName: 'Test App',
      webauthnModule: mockWebauthn(),
    })

  /** What `completePasskeyRegistration` writes, which `complete` reads back to check the signature. */
  const passkeyMeta = {
    counter: 0,
    publicKey: Buffer.from([1, 2, 3, 4]).toString('base64url'),
    transports: ['internal'],
  }

  it('is left out of the allowCredentials the browser is offered', async () => {
    const adapter = new MemoryAdapter<ProfileShape>()
    const id = await identity(adapter)
    await lapsed(adapter.credentials, { identityId: id, kind: 'passkey', metadata: passkeyMeta, secret: 'cred-1' })
    await adapter.credentials.create(
      {
        expiresAt: null,
        identityId: id,
        kind: 'passkey',
        lastUsedAt: null,
        metadata: passkeyMeta,
        revokedAt: null,
        secret: 'cred-live',
        tenantId: null,
      },
      {},
    )
    const intents = await provider(adapter, id).begin(
      passwordCtx(adapter) as never,
      {
        email: 'someone@b.com',
        sessionId: 's1',
      } as never,
    )
    const offered = JSON.stringify(intents)
    expect(offered).toContain('cred-live')
    expect(offered).not.toContain('cred-1')
  })

  /**
   * Through `begin` first: `complete` refuses a sessionId with no stored challenge with this same
   * `AUTH_PASSKEY_MISMATCH`, so without the challenge the assertion holds whatever the gate does.
   */
  const attempt = async (expiry: 'lapsed' | 'live'): Promise<string> => {
    const adapter = new MemoryAdapter<ProfileShape>()
    const id = await identity(adapter)
    if (expiry === 'live') {
      await adapter.credentials.create(
        {
          expiresAt: null,
          identityId: id,
          kind: 'passkey',
          lastUsedAt: null,
          metadata: passkeyMeta,
          revokedAt: null,
          secret: 'cred-1',
          tenantId: null,
        },
        {},
      )
    } else {
      await lapsed(adapter.credentials, { identityId: id, kind: 'passkey', metadata: passkeyMeta, secret: 'cred-1' })
    }
    const p = provider(adapter, id)
    const ctx = passwordCtx(adapter)
    await p.begin(ctx as never, { sessionId: 's1' } as never)
    try {
      const intents = await p.complete(ctx as never, { response: { id: 'cred-1' }, sessionId: 's1' } as never)
      return (intents[0] as { type: string } | undefined)?.type ?? 'no intents'
    } catch (err) {
      return (err as { code: string }).code
    }
  }

  it('cannot mint the session an identical live row mints', async () => {
    expect(await attempt('live')).toBe('startSession')
    expect(await attempt('lapsed')).toBe('AUTH_PASSKEY_MISMATCH')
  })
})

describe('a backup code past its expiresAt, on both implementations of the contract', () => {
  it('BackupCodesFacet neither counts it nor spends it', async () => {
    const adapter = new MemoryAdapter<ProfileShape>()
    const id = await identity(adapter)
    const facet = new BackupCodesFacet(adapter.credentials, CRYPTO)
    await lapsed(adapter.credentials, {
      identityId: id,
      kind: 'recovery',
      metadata: { purpose: 'mfa-backup-code' },
      secret: sha256('ABCD-1234'),
    })
    expect(await facet.remaining(id)).toBe(0)
    expect(await facet.verify(id, 'ABCD-1234')).toBe(false)

    // The control, without which both assertions above hold for a code that never matched: `generate`
    // hashes the *formatted* code and `_normalize` re-applies the grouping, so a bare hash matches nothing.
    const live = await identity(adapter)
    await adapter.credentials.create(
      {
        expiresAt: null,
        identityId: live,
        kind: 'recovery',
        lastUsedAt: null,
        metadata: { purpose: 'mfa-backup-code' },
        revokedAt: null,
        secret: sha256('ABCD-1234'),
        tenantId: null,
      },
      {},
    )
    expect(await facet.remaining(live)).toBe(1)
    expect(await facet.verify(live, 'ABCD-1234')).toBe(true)
  })

  it('MfaImpl.verifyBackupCode refuses it', async () => {
    const adapter = new MemoryAdapter<ProfileShape>()
    const id = await identity(adapter)
    const mfa = new MfaImpl(adapter.credentials, bus, {})
    await lapsed(adapter.credentials, {
      identityId: id,
      kind: 'recovery',
      metadata: { purpose: 'mfa-backup-code' },
      secret: sha256('abcd1234'),
    })
    expect(await mfa.verifyBackupCode(id, 'abcd1234')).toBe(false)

    const live = await identity(adapter)
    await adapter.credentials.create(
      {
        expiresAt: null,
        identityId: live,
        kind: 'recovery',
        lastUsedAt: null,
        metadata: { purpose: 'mfa-backup-code' },
        revokedAt: null,
        secret: sha256('abcd1234'),
        tenantId: null,
      },
      {},
    )
    expect(await mfa.verifyBackupCode(live, 'abcd1234')).toBe(true)
  })
})
