/**
 * Integration tests for the SQLite Drizzle OP stores. Uses bun:sqlite
 * via drizzle-orm/bun-sqlite so no extra peer-dep needs to be installed.
 *
 * Skipped under Node (vitest in CI). Bun's test runner picks it up
 * automatically; CI Node runs see an empty describe block and move on.
 */

import { describe, expect, it } from 'vitest'
import { authCreateDrizzleSqliteOidcOpStores, authGcDrizzleSqliteOidcOp } from '../sqlite'

const IS_BUN = typeof (globalThis as any).Bun !== 'undefined'

// describe.skipIf works in both bun:test and vitest; falsy-skips when not bun.
const onlyBun = IS_BUN ? describe : describe.skip

async function makeStores() {
  // Dynamic require so vitest (under Node) never resolves bun:sqlite at all.
  const { Database } = (await import('bun:sqlite' as any)) as {
    Database: new (path: string) => { exec(sql: string): void }
  }
  const { drizzle } = await import('drizzle-orm/bun-sqlite')
  const sqlite = new Database(':memory:')
  sqlite.exec(`
    CREATE TABLE oidc_clients (
      client_id TEXT PRIMARY KEY,
      client_secret_hash TEXT,
      redirect_uris TEXT NOT NULL,
      grant_types TEXT NOT NULL,
      response_types TEXT NOT NULL,
      token_endpoint_auth_method TEXT NOT NULL,
      scope TEXT NOT NULL,
      client_name TEXT,
      client_uri TEXT,
      logo_uri TEXT,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE oidc_codes (
      code TEXT PRIMARY KEY,
      client_id TEXT NOT NULL,
      identity_id TEXT NOT NULL,
      redirect_uri TEXT NOT NULL,
      scope TEXT NOT NULL,
      nonce TEXT,
      code_challenge TEXT,
      code_challenge_method TEXT,
      tenant_id TEXT,
      sid TEXT NOT NULL,
      exp INTEGER NOT NULL
    );
    CREATE TABLE oidc_access_tokens (
      token_hash TEXT PRIMARY KEY,
      client_id TEXT NOT NULL,
      identity_id TEXT NOT NULL,
      scope TEXT NOT NULL,
      tenant_id TEXT,
      exp INTEGER NOT NULL
    );
    CREATE TABLE oidc_refresh_tokens (
      token_hash TEXT PRIMARY KEY,
      family_id TEXT NOT NULL,
      client_id TEXT NOT NULL,
      identity_id TEXT NOT NULL,
      scope TEXT NOT NULL,
      tenant_id TEXT,
      exp INTEGER NOT NULL,
      consumed_at INTEGER
    );
    CREATE TABLE oidc_consents (
      identity_id TEXT NOT NULL,
      client_id TEXT NOT NULL,
      scope TEXT NOT NULL,
      granted_at INTEGER NOT NULL,
      PRIMARY KEY (identity_id, client_id)
    );
  `)
  const db = drizzle(sqlite as any)
  return { sqlite, db, stores: authCreateDrizzleSqliteOidcOpStores(db) }
}

onlyBun('authCreateDrizzleSqliteOidcOpStores - clients', () => {
  it('round-trips a client', async () => {
    const { stores } = await makeStores()
    await stores.clients.insert({
      client_id: 'app',
      client_secret_hash: 'hash',
      redirect_uris: ['https://app/cb'],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'client_secret_basic',
      scope: ['openid', 'profile'],
      client_name: 'Test',
      createdAt: 1700000000,
    })
    const found = await stores.clients.findById('app')
    expect(found?.client_id).toBe('app')
    expect(found?.redirect_uris).toEqual(['https://app/cb'])
    expect(found?.scope).toEqual(['openid', 'profile'])
    expect(found?.client_name).toBe('Test')
  })

  it('returns null for unknown client', async () => {
    const { stores } = await makeStores()
    expect(await stores.clients.findById('nope')).toBeNull()
  })
})

onlyBun('authCreateDrizzleSqliteOidcOpStores - codes', () => {
  it('consume is single-use', async () => {
    const { stores } = await makeStores()
    await stores.codes.insert({
      code: 'c1',
      client_id: 'app',
      identity_id: 'u',
      redirect_uri: 'https://app/cb',
      scope: ['openid'],
      nonce: null,
      code_challenge: null,
      code_challenge_method: null,
      tenant_id: null,
      sid: 's',
      exp: Date.now() + 60_000,
    })
    const first = await stores.codes.consume('c1', Date.now())
    expect(first?.code).toBe('c1')
    const replay = await stores.codes.consume('c1', Date.now())
    expect(replay).toBeNull()
  })

  it('expired code returns null', async () => {
    const { stores } = await makeStores()
    await stores.codes.insert({
      code: 'c2',
      client_id: 'app',
      identity_id: 'u',
      redirect_uri: 'https://app/cb',
      scope: ['openid'],
      nonce: null,
      code_challenge: null,
      code_challenge_method: null,
      tenant_id: null,
      sid: 's',
      exp: Date.now() - 1,
    })
    const out = await stores.codes.consume('c2', Date.now())
    expect(out).toBeNull()
  })
})

onlyBun('authCreateDrizzleSqliteOidcOpStores - access tokens', () => {
  it('insert + find + revoke lifecycle', async () => {
    const { stores } = await makeStores()
    await stores.accessTokens.insert({
      token_hash: 'h1',
      client_id: 'app',
      identity_id: 'u',
      scope: ['openid'],
      tenant_id: null,
      exp: Date.now() + 60_000,
    })
    const found = await stores.accessTokens.findByHash('h1', Date.now())
    expect(found?.identity_id).toBe('u')
    await stores.accessTokens.revokeByHash('h1')
    expect(await stores.accessTokens.findByHash('h1', Date.now())).toBeNull()
  })

  it('expired token is dropped on read', async () => {
    const { stores } = await makeStores()
    await stores.accessTokens.insert({
      token_hash: 'h-exp',
      client_id: 'app',
      identity_id: 'u',
      scope: ['openid'],
      tenant_id: null,
      exp: Date.now() - 1,
    })
    expect(await stores.accessTokens.findByHash('h-exp', Date.now())).toBeNull()
  })
})

onlyBun('authCreateDrizzleSqliteOidcOpStores - refresh tokens', () => {
  it('consume rotates and reuse triggers family revoke', async () => {
    const { stores } = await makeStores()
    const familyId = 'fam-1'
    await stores.refreshTokens.insert({
      token_hash: 'rt-1',
      family_id: familyId,
      client_id: 'app',
      identity_id: 'u',
      scope: ['openid', 'offline_access'],
      tenant_id: null,
      exp: Date.now() + 60_000,
      consumedAt: null,
    })
    const consumed = await stores.refreshTokens.consume('rt-1', Date.now())
    expect(consumed?.token_hash).toBe('rt-1')
    const replay = await stores.refreshTokens.consume('rt-1', Date.now())
    expect(replay).toBeNull()
    await stores.refreshTokens.revokeFamily(familyId)
    expect(await stores.refreshTokens.findByHash('rt-1', Date.now())).toBeNull()
  })
})

onlyBun('authCreateDrizzleSqliteOidcOpStores - consents', () => {
  it('upsert replaces scope on second call', async () => {
    const { stores } = await makeStores()
    await stores.consents.upsert({
      identity_id: 'u',
      client_id: 'app',
      scope: ['openid'],
      grantedAt: 1,
    })
    let row = await stores.consents.find('u', 'app')
    expect(row?.scope).toEqual(['openid'])
    await stores.consents.upsert({
      identity_id: 'u',
      client_id: 'app',
      scope: ['openid', 'email'],
      grantedAt: 2,
    })
    row = await stores.consents.find('u', 'app')
    expect(row?.scope).toEqual(['openid', 'email'])
    expect(row?.grantedAt).toBe(2)
  })

  it('different (identity, client) pairs do not collide', async () => {
    const { stores } = await makeStores()
    await stores.consents.upsert({ identity_id: 'a', client_id: 'app', scope: ['openid'], grantedAt: 1 })
    await stores.consents.upsert({ identity_id: 'b', client_id: 'app', scope: ['openid'], grantedAt: 1 })
    expect(await stores.consents.find('a', 'app')).not.toBeNull()
    expect(await stores.consents.find('b', 'app')).not.toBeNull()
  })
})

onlyBun('authGcDrizzleSqliteOidcOp', () => {
  it('prunes expired codes / access tokens / consumed refresh tokens', async () => {
    const { stores, db } = await makeStores()
    const now = Date.now()
    await stores.codes.insert({
      code: 'gc-code',
      client_id: 'app',
      identity_id: 'u',
      redirect_uri: 'x',
      scope: ['openid'],
      nonce: null,
      code_challenge: null,
      code_challenge_method: null,
      tenant_id: null,
      sid: 's',
      exp: now - 1,
    })
    await stores.accessTokens.insert({
      token_hash: 'gc-at',
      client_id: 'app',
      identity_id: 'u',
      scope: ['openid'],
      tenant_id: null,
      exp: now - 1,
    })
    await stores.refreshTokens.insert({
      token_hash: 'gc-rt',
      family_id: 'f',
      client_id: 'app',
      identity_id: 'u',
      scope: ['openid'],
      tenant_id: null,
      exp: now + 60_000,
      consumedAt: now - 1,
    })
    const removed = await authGcDrizzleSqliteOidcOp(db, now)
    expect(removed).toBe(3)
  })
})
