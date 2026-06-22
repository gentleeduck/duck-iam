import { describe, expect, it } from 'vitest'
import { AesGcmDataAtRest } from '../aes-gcm'

describe('AesGcmDataAtRest - decrypt hardening', () => {
  const KEY = 'a-very-long-master-key-that-is-32-bytes!!'
  const ctx = { identityId: 'identity-1', field: 'profile.email' }

  function makeAdapter(): AesGcmDataAtRest {
    return new AesGcmDataAtRest({ kid: 'k1', masterKey: KEY })
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
      code: 'AUTH/MISCONFIGURED',
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
      code: 'AUTH/MISCONFIGURED',
      meta: { detail: 'aes-256-gcm: auth tag must be 16 bytes' },
    })
  })

  it('rejects ciphertext with tampered ct payload -> generic auth-tag-mismatch error (no Node-error leak)', async () => {
    const a = makeAdapter()
    const ct = await a.encrypt('original', ctx)
    const parts = ct.split('$')
    // Flip the last char of the ct payload.
    const tamperedCt = parts[4]!.slice(0, -1) + (parts[4]!.slice(-1) === 'A' ? 'B' : 'A')
    const tampered = `${parts[0]}$${parts[1]}$${parts[2]}$${parts[3]}$${tamperedCt}`
    await expect(a.decrypt(tampered, ctx)).rejects.toMatchObject({
      code: 'AUTH/MISCONFIGURED',
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
      code: 'AUTH/MISCONFIGURED',
      meta: { detail: 'aes-256-gcm: auth-tag mismatch' },
    })
  })

  it('rejects ciphertext with wrong identityId context -> tag mismatch (DEK changed)', async () => {
    const a = makeAdapter()
    const ct = await a.encrypt('original', ctx)
    await expect(a.decrypt(ct, { identityId: 'other-identity', field: ctx.field })).rejects.toMatchObject({
      code: 'AUTH/MISCONFIGURED',
      meta: { detail: 'aes-256-gcm: auth-tag mismatch' },
    })
  })

  it('rejects malformed ciphertext (wrong prefix)', async () => {
    const a = makeAdapter()
    await expect(a.decrypt('not-the-right-shape', ctx)).rejects.toMatchObject({
      code: 'AUTH/MISCONFIGURED',
      meta: { detail: 'aes-256-gcm: malformed ciphertext' },
    })
  })

  it('rejects ciphertext with unknown kid (not in ring)', async () => {
    const a = makeAdapter()
    const ct = await a.encrypt('plain', ctx)
    const parts = ct.split('$')
    const tampered = `${parts[0]}$unknown-kid$${parts[2]}$${parts[3]}$${parts[4]}`
    await expect(a.decrypt(tampered, ctx)).rejects.toMatchObject({
      code: 'AUTH/MISCONFIGURED',
    })
  })
})
