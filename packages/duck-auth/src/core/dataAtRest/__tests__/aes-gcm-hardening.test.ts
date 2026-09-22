import { describe, expect, it } from 'vitest'
import { AuthAesGcmDataAtRest } from '../aes-gcm'

describe('AuthAesGcmDataAtRest - decrypt hardening', () => {
  const KEY = 'a-very-long-master-key-that-is-32-bytes!!'
  const ctx = { identityId: 'identity-1', field: 'profile.email' }

  function makeAdapter(): AuthAesGcmDataAtRest {
    return new AuthAesGcmDataAtRest({ kid: 'k1', masterKey: KEY })
  }

  it('round-trips a normal ciphertext', async () => {
    const a = makeAdapter()
    const ct = await a.encrypt('plain-text', ctx)
    expect(await a.decrypt(ct, ctx)).toBe('plain-text')
  })

  it('rejects ciphertext with non-12-byte IV', async () => {
    const a = makeAdapter()
    const ct = await a.encrypt('plain', ctx)
    // Parse, replace the IV with an 8-byte one.
    const parts = ct.split('$')
    const eightByteIv = Buffer.alloc(8).toString('base64url')
    const tampered = `${parts[0]}$${parts[1]}$${eightByteIv}$${parts[3]}$${parts[4]}`
    await expect(a.decrypt(tampered, ctx)).rejects.toMatchObject({
      code: 'AUTH_INVALID_PARAMETERS',
      meta: { detail: 'aes-256-gcm: IV must be 12 bytes' },
    })
  })

  it('rejects ciphertext with non-16-byte auth tag', async () => {
    const a = makeAdapter()
    const ct = await a.encrypt('plain', ctx)
    const parts = ct.split('$')
    const eightByteTag = Buffer.alloc(8).toString('base64url')
    const tampered = `${parts[0]}$${parts[1]}$${parts[2]}$${eightByteTag}$${parts[4]}`
    await expect(a.decrypt(tampered, ctx)).rejects.toMatchObject({
      code: 'AUTH_INVALID_PARAMETERS',
      meta: { detail: 'aes-256-gcm: auth tag must be 16 bytes' },
    })
  })

  it('rejects ciphertext with tampered ct payload -> generic auth-tag-mismatch error (no Node-error leak)', async () => {
    const a = makeAdapter()
    const ct = await a.encrypt('original', ctx)
    const parts = ct.split('$')
    // Flip a byte, not a base64url char: the final char carries padding bits that a
    // char swap can leave decoding to the identical bytes, so tampering may not land.
    const ctBytes = Buffer.from(parts[4]!, 'base64url')
    ctBytes[0] = ctBytes[0]! ^ 0xff
    const tampered = `${parts[0]}$${parts[1]}$${parts[2]}$${parts[3]}$${ctBytes.toString('base64url')}`
    await expect(a.decrypt(tampered, ctx)).rejects.toMatchObject({
      code: 'AUTH_INVALID_PARAMETERS',
      meta: { detail: 'aes-256-gcm: auth-tag mismatch' },
    })
  })

  it('rejects ciphertext with tampered tag -> generic auth-tag-mismatch (not Node-error)', async () => {
    const a = makeAdapter()
    const ct = await a.encrypt('original', ctx)
    const parts = ct.split('$')
    // Flip a byte in the tag.
    const tagBytes = Buffer.from(parts[3]!, 'base64url')
    tagBytes[0] = tagBytes[0]! ^ 0xff
    const tamperedTag = tagBytes.toString('base64url')
    const tampered = `${parts[0]}$${parts[1]}$${parts[2]}$${tamperedTag}$${parts[4]}`
    await expect(a.decrypt(tampered, ctx)).rejects.toMatchObject({
      code: 'AUTH_INVALID_PARAMETERS',
      meta: { detail: 'aes-256-gcm: auth-tag mismatch' },
    })
  })

  it('rejects ciphertext with wrong identityId context -> tag mismatch (DEK changed)', async () => {
    const a = makeAdapter()
    const ct = await a.encrypt('original', ctx)
    await expect(a.decrypt(ct, { identityId: 'other-identity', field: ctx.field })).rejects.toMatchObject({
      code: 'AUTH_INVALID_PARAMETERS',
      meta: { detail: 'aes-256-gcm: auth-tag mismatch' },
    })
  })

  it('rejects malformed ciphertext (wrong prefix)', async () => {
    const a = makeAdapter()
    await expect(a.decrypt('not-the-right-shape', ctx)).rejects.toMatchObject({
      code: 'AUTH_INVALID_PARAMETERS',
      meta: { detail: 'aes-256-gcm: malformed ciphertext' },
    })
  })

  it('rejects ciphertext with unknown kid (not in ring)', async () => {
    const a = makeAdapter()
    const ct = await a.encrypt('plain', ctx)
    const parts = ct.split('$')
    const tampered = `${parts[0]}$unknown-kid$${parts[2]}$${parts[3]}$${parts[4]}`
    await expect(a.decrypt(tampered, ctx)).rejects.toMatchObject({
      code: 'AUTH_MISCONFIGURED',
    })
  })
})

/**
 * The ciphertext layout is `$`-separated and the kid is written into it verbatim, so a kid carrying a
 * `$` produces a six-field ciphertext that `decrypt` rejects as malformed. Encryption never complains,
 * which makes it the worst shape of misconfiguration: writes succeed and every read of them fails.
 */
describe('AuthAesGcmDataAtRest - kid cannot collide with the field separator', () => {
  const KEY = 'x'.repeat(32)

  it.each([['key$1'], ['prod$2026'], ['$'], ['']])('refuses kid %j at construction', (kid) => {
    expect(() => new AuthAesGcmDataAtRest({ kid, masterKey: KEY })).toThrow(
      expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
    )
  })

  it('refuses it in previousKeys too, which is where a rotation would smuggle one in', () => {
    expect(
      () => new AuthAesGcmDataAtRest({ kid: 'k2', masterKey: KEY, previousKeys: [{ kid: 'k$1', masterKey: KEY }] }),
    ).toThrow(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))
  })

  it('still accepts the ordinary shapes an operator uses', async () => {
    for (const kid of ['k1', '2026-05-01', 'prod.v2', 'a_b-c']) {
      const a = new AuthAesGcmDataAtRest({ kid, masterKey: KEY })
      const ctx = { field: 'email', identityId: 'u1' }
      expect(await a.decrypt(await a.encrypt('secret@example.com', ctx), ctx)).toBe('secret@example.com')
    }
  })
})
