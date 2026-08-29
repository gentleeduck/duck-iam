/**
 * The DEK here is deterministic: `sha256(masterKey || identityId || field)`. The
 * same field of the same identity is always encrypted under the same key, which
 * means the twelve-byte IV is the only thing keeping two ciphertexts apart.
 *
 * That makes IV uniqueness the single catastrophic failure in this adapter. Reuse
 * one IV under one key and GCM stops protecting anything: the XOR of two
 * ciphertexts is the XOR of their plaintexts, and the authentication tag becomes
 * forgeable. Nothing tested it, so a change that hoisted the IV out of `encrypt`
 * or seeded it from the context would have looked fine in review and passed the
 * existing round-trip tests.
 *
 * The rest of the file covers the other property a deterministic-DEK design
 * needs: that the context genuinely separates keys, so one field's ciphertext
 * cannot be decrypted as another's.
 */
import { Buffer } from 'node:buffer'
import { describe, expect, it } from 'vitest'
import { AuthAesGcmDataAtRest } from '../aes-gcm'

const KEY_A = Buffer.alloc(32, 1)
const KEY_B = Buffer.alloc(32, 2)
const adapter = new AuthAesGcmDataAtRest({ kid: 'k1', masterKey: KEY_A })
const ctx = { field: 'ssn', identityId: 'user-1' }

/** `aes-256-gcm$<kid>$<iv>$<tag>$<ct>` */
const parts = (ciphertext: string) => ciphertext.split('$')
const ivOf = (ciphertext: string) => parts(ciphertext)[2] as string
const tagOf = (ciphertext: string) => parts(ciphertext)[3] as string
const bodyOf = (ciphertext: string) => parts(ciphertext)[4] as string

describe('the IV is fresh for every encryption', () => {
  it('never repeats across a thousand encryptions of the same value in the same context', async () => {
    // The exact scenario that breaks GCM: one key, one plaintext, many writes.
    const seen = new Set<string>()
    for (let i = 0; i < 1000; i++) seen.add(ivOf(await adapter.encrypt('same-value', ctx)))
    expect(seen.size).toBe(1000)
  })

  it('is twelve bytes, the size GCM expects', async () => {
    const iv = Buffer.from(ivOf(await adapter.encrypt('x', ctx)), 'base64url')
    expect(iv).toHaveLength(12)
  })

  it('spreads over the whole byte range rather than a corner of it', async () => {
    const bytes = new Set<number>()
    for (let i = 0; i < 200; i++) {
      for (const b of Buffer.from(ivOf(await adapter.encrypt('x', ctx)), 'base64url')) bytes.add(b)
    }
    // A counter or a timestamp would touch a narrow band of values.
    expect(bytes.size).toBeGreaterThan(200)
  })

  it('does not derive the IV from the plaintext', async () => {
    // A content-derived IV is deterministic, which is the same failure by another
    // route: equal plaintexts would collide.
    const first = await adapter.encrypt('identical', ctx)
    const second = await adapter.encrypt('identical', ctx)
    expect(ivOf(first)).not.toBe(ivOf(second))
  })

  it('does not derive the IV from the context', async () => {
    const a = await adapter.encrypt('x', { field: 'ssn', identityId: 'user-1' })
    const b = await adapter.encrypt('x', { field: 'ssn', identityId: 'user-1' })
    expect(ivOf(a)).not.toBe(ivOf(b))
  })

  it('two adapters sharing a key still produce distinct IVs', async () => {
    // Two processes with the same configuration must not march in step.
    const other = new AuthAesGcmDataAtRest({ kid: 'k1', masterKey: KEY_A })
    const mine = new Set<string>()
    const theirs = new Set<string>()
    for (let i = 0; i < 100; i++) {
      mine.add(ivOf(await adapter.encrypt('x', ctx)))
      theirs.add(ivOf(await other.encrypt('x', ctx)))
    }
    for (const iv of theirs) expect(mine.has(iv)).toBe(false)
  })
})

describe('equal plaintexts do not produce equal ciphertexts', () => {
  it('the whole ciphertext differs between two encryptions of one value', async () => {
    const first = await adapter.encrypt('same-value', ctx)
    const second = await adapter.encrypt('same-value', ctx)
    expect(first).not.toBe(second)
    expect(bodyOf(first)).not.toBe(bodyOf(second))
    expect(tagOf(first)).not.toBe(tagOf(second))
  })

  it('a thousand encryptions of one value yield a thousand distinct ciphertexts', async () => {
    const seen = new Set<string>()
    for (let i = 0; i < 1000; i++) seen.add(await adapter.encrypt('same-value', ctx))
    expect(seen.size).toBe(1000)
  })

  it('the ciphertext body does not leak the plaintext', async () => {
    const encrypted = await adapter.encrypt('super-secret-national-id', ctx)
    expect(encrypted).not.toContain('super-secret-national-id')
    expect(Buffer.from(bodyOf(encrypted), 'base64url').toString('utf8')).not.toContain('secret')
  })

  it('every one of them still decrypts', async () => {
    for (let i = 0; i < 50; i++) {
      const encrypted = await adapter.encrypt('same-value', ctx)
      expect(await adapter.decrypt(encrypted, ctx)).toBe('same-value')
    }
  })
})

describe('the context separates keys', () => {
  it('a different field cannot decrypt it', async () => {
    const encrypted = await adapter.encrypt('secret', { field: 'ssn', identityId: 'user-1' })
    await expect(adapter.decrypt(encrypted, { field: 'dob', identityId: 'user-1' })).rejects.toThrow()
  })

  it('a different identity cannot decrypt it', async () => {
    // The one that matters most: one user's ciphertext must not open under
    // another user's context, whatever else they share.
    const encrypted = await adapter.encrypt('secret', { field: 'ssn', identityId: 'user-1' })
    await expect(adapter.decrypt(encrypted, { field: 'ssn', identityId: 'user-2' })).rejects.toThrow()
  })

  it('a different master key cannot decrypt it', async () => {
    const encrypted = await adapter.encrypt('secret', ctx)
    const stranger = new AuthAesGcmDataAtRest({ kid: 'k1', masterKey: KEY_B })
    await expect(stranger.decrypt(encrypted, ctx)).rejects.toThrow()
  })

  it('FINDING: the context is concatenated, so a boundary can be shifted', async () => {
    // The DEK is sha256(key || identityId || field) with no separator, so
    // ('ab', 'c') and ('a', 'bc') hash the same bytes and derive the same key.
    // Reaching it needs an identityId and a field an attacker controls together,
    // and field names come from the library rather than a request, so this is a
    // property of the construction rather than a live hole. Pinned because a
    // future caller passing a user-supplied field name would make it one.
    const encrypted = await adapter.encrypt('secret', { field: 'c', identityId: 'ab' })
    expect(await adapter.decrypt(encrypted, { field: 'bc', identityId: 'a' })).toBe('secret')
  })
})

describe('tampering is refused', () => {
  it('refuses a flipped byte in the ciphertext body', async () => {
    const encrypted = await adapter.encrypt('secret', ctx)
    const body = Buffer.from(bodyOf(encrypted), 'base64url')
    body[0] = (body[0] as number) ^ 0xff
    const [alg, kid, iv, tag] = parts(encrypted)
    await expect(adapter.decrypt(`${alg}$${kid}$${iv}$${tag}$${body.toString('base64url')}`, ctx)).rejects.toThrow()
  })

  it('refuses a flipped byte in the tag', async () => {
    const encrypted = await adapter.encrypt('secret', ctx)
    const tag = Buffer.from(tagOf(encrypted), 'base64url')
    tag[0] = (tag[0] as number) ^ 0xff
    const [alg, kid, iv, , body] = parts(encrypted)
    await expect(adapter.decrypt(`${alg}$${kid}$${iv}$${tag.toString('base64url')}$${body}`, ctx)).rejects.toThrow()
  })

  it('refuses a swapped IV, which is what makes the IV authenticated in effect', async () => {
    const first = await adapter.encrypt('secret-one', ctx)
    const second = await adapter.encrypt('secret-two', ctx)
    const [alg, kid, , tag, body] = parts(first)
    await expect(adapter.decrypt(`${alg}$${kid}$${ivOf(second)}$${tag}$${body}`, ctx)).rejects.toThrow()
  })

  it('refuses a tag and body taken from different ciphertexts', async () => {
    const first = await adapter.encrypt('secret-one', ctx)
    const second = await adapter.encrypt('secret-two', ctx)
    const [alg, kid, iv] = parts(first)
    await expect(adapter.decrypt(`${alg}$${kid}$${iv}$${tagOf(second)}$${bodyOf(first)}`, ctx)).rejects.toThrow()
  })

  it('refuses an unknown kid rather than guessing a key', async () => {
    const encrypted = await adapter.encrypt('secret', ctx)
    const [alg, , iv, tag, body] = parts(encrypted)
    await expect(adapter.decrypt(`${alg}$unknown-kid$${iv}$${tag}$${body}`, ctx)).rejects.toThrow()
  })

  it('refuses malformed envelopes without throwing something unhelpful', async () => {
    for (const bad of ['', 'not-an-envelope', 'aes-256-gcm$k1', 'aes-256-gcm$k1$$$', '$$$$', 'a$b$c$d$e$f']) {
      await expect(adapter.decrypt(bad, ctx)).rejects.toThrow()
    }
  })
})

describe('key rotation does not strand ciphertext', () => {
  it('a key kept in the previous ring still decrypts what it wrote', async () => {
    const old = new AuthAesGcmDataAtRest({ kid: 'k1', masterKey: KEY_A })
    const encrypted = await old.encrypt('written-under-k1', ctx)

    const rotated = new AuthAesGcmDataAtRest({
      kid: 'k2',
      masterKey: KEY_B,
      previousKeys: [{ kid: 'k1', masterKey: KEY_A }],
    })
    expect(await rotated.decrypt(encrypted, ctx)).toBe('written-under-k1')
  })

  it('new writes carry the new kid', async () => {
    const rotated = new AuthAesGcmDataAtRest({
      kid: 'k2',
      masterKey: KEY_B,
      previousKeys: [{ kid: 'k1', masterKey: KEY_A }],
    })
    expect(parts(await rotated.encrypt('fresh', ctx))[1]).toBe('k2')
  })

  it('refuses a duplicate kid across the ring, which would make lookup ambiguous', () => {
    expect(
      () =>
        new AuthAesGcmDataAtRest({
          kid: 'k1',
          masterKey: KEY_A,
          previousKeys: [{ kid: 'k1', masterKey: KEY_B }],
        }),
    ).toThrow(/AUTH_MISCONFIGURED/)
  })

  it('IVs stay unique across a rotation', async () => {
    const rotated = new AuthAesGcmDataAtRest({
      kid: 'k2',
      masterKey: KEY_B,
      previousKeys: [{ kid: 'k1', masterKey: KEY_A }],
    })
    const seen = new Set<string>()
    for (let i = 0; i < 200; i++) seen.add(ivOf(await rotated.encrypt('x', ctx)))
    expect(seen.size).toBe(200)
  })
})

describe('the values it is asked to protect', () => {
  it('round-trips an empty string', async () => {
    expect(await adapter.decrypt(await adapter.encrypt('', ctx), ctx)).toBe('')
  })

  it('round-trips unicode and emoji without mangling them', async () => {
    for (const value of ['naïve', '🦆🦆🦆', '中文', 'café', 'a b']) {
      expect(await adapter.decrypt(await adapter.encrypt(value, ctx), ctx)).toBe(value)
    }
  })

  it('FINDING: a value between about 786KB and 1MiB encrypts and can never be decrypted', async () => {
    // `encrypt` caps the PLAINTEXT at 1 MiB. `decrypt` caps the CIPHERTEXT
    // ENVELOPE at the same 1 MiB. Base64 expands by about a third, so a 1 MiB
    // plaintext produces a 1,398,157 character envelope that `decrypt` refuses
    // as oversize. The write succeeds and the row is stored; the read throws.
    // Measured break point: 786,000 bytes round-trips, 800,000 does not.
    const doomed = 'x'.repeat(1_000_000)
    const encrypted = await adapter.encrypt(doomed, ctx)
    expect(encrypted.length).toBeGreaterThan(1_048_576)
    await expect(adapter.decrypt(encrypted, ctx)).rejects.toMatchObject({ code: 'AUTH_MISCONFIGURED' })
  })

  it('round-trips the largest value that survives the envelope expansion', async () => {
    const safe = 'x'.repeat(786_000)
    expect(await adapter.decrypt(await adapter.encrypt(safe, ctx), ctx)).toBe(safe)
  })

  it('refuses a value past the size cap rather than encrypting it', async () => {
    await expect(adapter.encrypt('x'.repeat(1_048_577), ctx)).rejects.toThrow()
  })

  it('refuses a non-string', async () => {
    for (const value of [42, null, undefined, {}, []]) {
      await expect(adapter.encrypt(value as never, ctx)).rejects.toThrow()
    }
  })
})
