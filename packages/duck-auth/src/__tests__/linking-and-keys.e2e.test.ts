/**
 * E2E: provider linking and API keys against REAL Postgres.
 *
 * Provider linking is where two of this audit's defects lived. `identities.link`
 * and `findByProviderSub` were both a SQL syntax error on Postgres, a stray
 * bracket before `::jsonb`, so every social-account link threw. The compliance
 * matrix caught them at the store; nothing exercised the flow that calls them, and
 * the flow is what an app actually reaches for. This suite closes that.
 *
 * API keys had no coverage at all. They are long-lived bearer secrets whose only
 * defence is that revocation reaches the row, which is exactly the sort of claim a
 * memory store answers from the object it is already holding.
 *
 * Skips when DUCKAUTH_E2E_DATABASE_URL is unset; `globalSetup` provisions a
 * container when docker is available.
 */
import { Pool } from 'pg'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { drizzlePgStorage } from '~/adapters/drizzle/pg'
import { randomToken, sha256 } from '~/core/crypto'
import { AuthEngine } from '~/core/engine'
import { InMemoryEvents } from '~/core/events'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { ApiKeysFacet } from '~/providers/api-key'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { applyPgSchema, databaseUrl, e2ePrefix } from '~/test/e2e-env'

const URL = databaseUrl()
const suite = URL ? describe : describe.skip

type Profile = { username: string; email: string }

suite('E2E provider linking and API keys on real Postgres', () => {
  let pool: Pool
  let auth: AuthEngine<Profile>
  let stores: ReturnType<typeof drizzlePgStorage<Profile>>
  let keys: ApiKeysFacet
  const planted: string[] = []

  async function newUser(label: string): Promise<string> {
    const tag = `${label}-${e2ePrefix()}`
    const identity = await auth.identities.create({ profile: { email: `${tag}@test.local`, username: tag } })
    planted.push(identity.id)
    return identity.id
  }

  const sub = (label: string) => `${label}-${e2ePrefix()}`

  beforeAll(async () => {
    pool = new Pool({ connectionString: URL })
    await applyPgSchema(pool)
    stores = drizzlePgStorage<Profile>(URL as string)
    auth = new AuthEngine<Profile>({
      baseUrl: 'https://app.test',
      stores: { credentials: stores.credentials, identities: stores.identities, sessions: stores.sessions },
      transport: new CookieTransport({ name: 'duck-sid', secure: false }),
    })
    auth.providers.register(passwords<Profile>({ hasher: new ScryptHasher({ keylen: 32, N: 1 << 10 }) }))
    keys = new ApiKeysFacet(stores.credentials, new InMemoryEvents(), { randomToken, sha256 })
  }, 60_000)

  afterAll(async () => {
    if (pool && planted.length > 0) {
      await pool.query('DELETE FROM auth_identities WHERE id = ANY($1::uuid[])', [planted])
    }
    await pool?.end()
  })

  describe('linking a provider account', () => {
    it('links, and the account is then findable by its provider sub', async () => {
      // The whole path that was a SQL syntax error before this audit: link writes
      // the jsonb array, findByProviderSub reads it back with a containment query.
      const id = await newUser('link')
      const providerSub = sub('google')

      await auth.flows.linkProvider({ identityId: id, providerId: 'oauth:authGoogle', providerSub })

      const found = await stores.identities.findByProviderSub('oauth:authGoogle', providerSub)
      expect(found?.id).toBe(id)
    })

    it('keeps several providers on one account', async () => {
      const id = await newUser('link-many')
      const g = sub('google')
      const gh = sub('github')
      await auth.flows.linkProvider({ identityId: id, providerId: 'oauth:authGoogle', providerSub: g })
      await auth.flows.linkProvider({ identityId: id, providerId: 'oauth:authGithub', providerSub: gh })

      const row = await stores.identities.findById(id)
      expect(row?.providers.map((p) => p.providerId).sort()).toEqual(['oauth:authGithub', 'oauth:authGoogle'])
    })

    it('is idempotent: linking the same pair twice does not duplicate it', async () => {
      const id = await newUser('link-twice')
      const providerSub = sub('google')
      await auth.flows.linkProvider({ identityId: id, providerId: 'oauth:authGoogle', providerSub })
      await auth.flows.linkProvider({ identityId: id, providerId: 'oauth:authGoogle', providerSub })

      const row = await stores.identities.findById(id)
      expect(row?.providers.filter((p) => p.providerId === 'oauth:authGoogle')).toHaveLength(1)
    })

    it('refuses to attach one provider account to a second identity', async () => {
      // Account takeover by linking: if the same Google account could hang off two
      // identities, signing in with it would be ambiguous.
      const mine = await newUser('link-mine')
      const theirs = await newUser('link-theirs')
      const providerSub = sub('shared')
      await auth.flows.linkProvider({ identityId: mine, providerId: 'oauth:authGoogle', providerSub })

      await expect(
        auth.flows.linkProvider({ identityId: theirs, providerId: 'oauth:authGoogle', providerSub }),
      ).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
    })

    it('refuses an unknown identity', async () => {
      await expect(
        auth.flows.linkProvider({
          identityId: '00000000-0000-4000-8000-000000000000',
          providerId: 'oauth:authGoogle',
          providerSub: sub('ghost'),
        }),
      ).rejects.toMatchObject({ code: 'AUTH_UNAUTHENTICATED' })
    })

    it('refuses a malformed provider id without echoing it back', async () => {
      const id = await newUser('link-bad-id')
      await expect(
        auth.flows.linkProvider({ identityId: id, providerId: 'x'.repeat(200), providerSub: sub('s') }),
      ).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED', meta: { providerId: 'invalid' } })
    })

    it('refuses an oversize provider sub', async () => {
      const id = await newUser('link-bad-sub')
      await expect(
        auth.flows.linkProvider({ identityId: id, providerId: 'oauth:authGoogle', providerSub: 'y'.repeat(600) }),
      ).rejects.toMatchObject({ code: 'AUTH_PROVIDER_FAILED' })
    })

    it('a soft-deleted account is not findable by its provider sub', async () => {
      const id = await newUser('link-deleted')
      const providerSub = sub('google')
      await auth.flows.linkProvider({ identityId: id, providerId: 'oauth:authGoogle', providerSub })
      await stores.identities.softDelete(id, 60_000)

      expect(await stores.identities.findByProviderSub('oauth:authGoogle', providerSub)).toBeNull()
    })

    it('frees the provider sub once the holder is soft-deleted', async () => {
      // Otherwise a deleted account holds someone's Google login hostage forever.
      const first = await newUser('link-free-a')
      const second = await newUser('link-free-b')
      const providerSub = sub('google')
      await auth.flows.linkProvider({ identityId: first, providerId: 'oauth:authGoogle', providerSub })
      await stores.identities.softDelete(first, 60_000)

      await auth.flows.linkProvider({ identityId: second, providerId: 'oauth:authGoogle', providerSub })
      expect((await stores.identities.findByProviderSub('oauth:authGoogle', providerSub))?.id).toBe(second)
    })
  })

  describe('unlinking', () => {
    it('removes only the named provider', async () => {
      const id = await newUser('unlink')
      const g = sub('google')
      const gh = sub('github')
      await auth.flows.linkProvider({ identityId: id, providerId: 'oauth:authGoogle', providerSub: g })
      await auth.flows.linkProvider({ identityId: id, providerId: 'oauth:authGithub', providerSub: gh })

      await auth.flows.unlinkProvider({ identityId: id, providerId: 'oauth:authGoogle' })

      expect(await stores.identities.findByProviderSub('oauth:authGoogle', g)).toBeNull()
      expect((await stores.identities.findByProviderSub('oauth:authGithub', gh))?.id).toBe(id)
    })

    it('lets the provider sub be linked again afterwards', async () => {
      const id = await newUser('unlink-relink')
      const providerSub = sub('google')
      // A second link, so removing the first is not the lockout the flow refuses.
      await auth.flows.linkProvider({ identityId: id, providerId: 'oauth:authGithub', providerSub: sub('gh') })
      await auth.flows.linkProvider({ identityId: id, providerId: 'oauth:authGoogle', providerSub })
      await auth.flows.unlinkProvider({ identityId: id, providerId: 'oauth:authGoogle' })
      await auth.flows.linkProvider({ identityId: id, providerId: 'oauth:authGoogle', providerSub })

      expect((await stores.identities.findByProviderSub('oauth:authGoogle', providerSub))?.id).toBe(id)
    })

    it('refuses to unlink the last way into an account', async () => {
      // Otherwise "disconnect Google" on an account with no password locks the
      // owner out permanently, and the library is the only thing that can see it.
      const id = await newUser('unlink-lockout')
      await auth.flows.linkProvider({ identityId: id, providerId: 'oauth:authGoogle', providerSub: sub('only') })

      await expect(auth.flows.unlinkProvider({ identityId: id, providerId: 'oauth:authGoogle' })).rejects.toMatchObject(
        { code: 'AUTH_PROVIDER_FAILED' },
      )
    })

    it('allows the lockout when the caller says so explicitly', async () => {
      const id = await newUser('unlink-forced')
      const providerSub = sub('only')
      await auth.flows.linkProvider({ identityId: id, providerId: 'oauth:authGoogle', providerSub })

      await auth.flows.unlinkProvider({ allowLockout: true, identityId: id, providerId: 'oauth:authGoogle' })
      expect(await stores.identities.findByProviderSub('oauth:authGoogle', providerSub)).toBeNull()
    })

    it('a password counts as another way in, so the last link can go', async () => {
      const id = await newUser('unlink-has-pw')
      const providerSub = sub('google')
      await auth.flows.linkProvider({ identityId: id, providerId: 'oauth:authGoogle', providerSub })
      await auth.passwords.set(id, 'correct-horse-battery', stores.credentials)

      await auth.flows.unlinkProvider({ identityId: id, providerId: 'oauth:authGoogle' })
      expect(await stores.identities.findByProviderSub('oauth:authGoogle', providerSub)).toBeNull()
    })
  })

  describe('API keys', () => {
    it('issues a key that verifies back to its owner', async () => {
      const id = await newUser('key-issue')
      const { plaintext } = await keys.create(id, { name: 'ci', scopes: ['read'] })

      const verified = await keys.verify(plaintext)
      expect(verified.identityId).toBe(id)
      expect(verified.scopes).toEqual(['read'])
    })

    it('never returns the plaintext again', async () => {
      // Only the hash is stored; a listing that could reproduce the secret would
      // make a database read equivalent to holding every key.
      const id = await newUser('key-once')
      const { plaintext } = await keys.create(id, { name: 'ci', scopes: ['read'] })
      const listed = await keys.list(id)

      expect(JSON.stringify(listed)).not.toContain(plaintext)
    })

    it('refuses a revoked key, and says so distinctly', async () => {
      const id = await newUser('key-revoke')
      const { key, plaintext } = await keys.create(id, { name: 'ci', scopes: ['read'] })
      await keys.revoke(key.id)

      await expect(keys.verify(plaintext)).rejects.toMatchObject({ code: 'AUTH_APIKEY_REVOKED' })
    })

    it('the revocation is in the row, not in this process', async () => {
      // A second facet reading the same table fresh must refuse it too.
      const id = await newUser('key-revoke-row')
      const { key, plaintext } = await keys.create(id, { name: 'ci', scopes: ['read'] })
      await keys.revoke(key.id)

      const otherProcess = new ApiKeysFacet(stores.credentials, new InMemoryEvents(), { randomToken, sha256 })
      await expect(otherProcess.verify(plaintext)).rejects.toMatchObject({ code: 'AUTH_APIKEY_REVOKED' })
    })

    it('a revoked key drops out of the listing', async () => {
      const id = await newUser('key-list')
      const a = await keys.create(id, { name: 'keep', scopes: ['read'] })
      const b = await keys.create(id, { name: 'drop', scopes: ['read'] })
      await keys.revoke(b.key.id)

      const listed = await keys.list(id)
      expect(listed.map((k) => k.id)).toEqual([a.key.id])
    })

    it('refuses a key that was never issued', async () => {
      await expect(keys.verify(`duck_sk_${e2ePrefix()}`)).rejects.toMatchObject({ code: 'AUTH_APIKEY_INVALID' })
    })

    it('refuses a string without the expected prefix', async () => {
      await expect(keys.verify('not-even-close')).rejects.toMatchObject({ code: 'AUTH_APIKEY_INVALID' })
    })

    it('refuses an absurdly long candidate rather than hashing it', async () => {
      await expect(keys.verify('x'.repeat(5000))).rejects.toMatchObject({ code: 'AUTH_APIKEY_INVALID' })
    })

    it('rotating issues a new secret and kills the old one', async () => {
      const id = await newUser('key-rotate')
      const first = await keys.create(id, { name: 'ci', scopes: ['read'] })
      const rotated = await keys.rotate(first.key.id)

      expect(rotated.plaintext).not.toBe(first.plaintext)
      expect((await keys.verify(rotated.plaintext)).identityId).toBe(id)
      await expect(keys.verify(first.plaintext)).rejects.toMatchObject({ code: 'AUTH_APIKEY_REVOKED' })
    })

    it('a key belonging to one identity does not verify as another', async () => {
      const mine = await newUser('key-mine')
      const theirs = await newUser('key-theirs')
      const { plaintext } = await keys.create(mine, { name: 'ci', scopes: ['read'] })

      expect((await keys.verify(plaintext)).identityId).not.toBe(theirs)
    })

    it('keys survive alongside each other', async () => {
      const id = await newUser('key-many')
      const a = await keys.create(id, { name: 'a', scopes: ['read'] })
      const b = await keys.create(id, { name: 'b', scopes: ['write'] })

      expect((await keys.verify(a.plaintext)).scopes).toEqual(['read'])
      expect((await keys.verify(b.plaintext)).scopes).toEqual(['write'])
    })

    it('erasing the identity takes its keys with it', async () => {
      const id = await newUser('key-cascade')
      const { plaintext } = await keys.create(id, { name: 'ci', scopes: ['read'] })
      await stores.identities.erase(id)

      await expect(keys.verify(plaintext)).rejects.toMatchObject({ code: 'AUTH_APIKEY_INVALID' })
    })
  })
})
