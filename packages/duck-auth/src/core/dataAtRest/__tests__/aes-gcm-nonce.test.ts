/**
 * The DEK here is deterministic: HKDF over the master key and the context. The
 * same field of the same identity is always encrypted under the same key, which
 * means the twelve-byte IV is the only thing keeping two ciphertexts apart.
 */
import { Buffer } from 'node:buffer'
import { createCipheriv, createHash, randomBytes } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { AuthAesGcmDataAtRest } from '../aes-gcm'

const KEY_A = Buffer.alloc(32, 1)
const KEY_B = Buffer.alloc(32, 2)
const adapter = new AuthAesGcmDataAtRest({ kid: 'k1', masterKey: KEY_A })
const ctx = { field: 'ssn', identityId: 'user-1' }

/** What the adapter wrote before the context was length-prefixed, built the way it built it. */
function legacyCiphertext(plain: string, masterKey: Buffer, kid: string, context: typeof ctx): string {
  const dek = createHash('sha256').update(masterKey).update(context.identityId).update(context.field).digest()
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', dek, iv)
  const body = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()])
  const tag = cipher.getAuthTag()
  return `aes-256-gcm$${kid}$${iv.toString('base64url')}$${tag.toString('base64url')}$${body.toString('base64url')}`
}

/** `<alg>$<kid>$<iv>$<tag>$<ct>` */
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

  it('a shifted boundary is a different key', async () => {
    // ('ab', 'c') and ('a', 'bc') flatten to the same bytes unless each component
    // carries its own length.
    const encrypted = await adapter.encrypt('secret', { field: 'c', identityId: 'ab' })
    await expect(adapter.decrypt(encrypted, { field: 'bc', identityId: 'a' })).rejects.toThrow()
  })
})

describe('the legacy format is read but never written', () => {
  it('writes the versioned algorithm', async () => {
    expect(parts(await adapter.encrypt('secret', ctx))[0]).toBe('aes-256-gcm.v2')
  })

  it('still decrypts a ciphertext written before the context was length-prefixed', async () => {
    expect(await adapter.decrypt(legacyCiphertext('secret', KEY_A, 'k1', ctx), ctx)).toBe('secret')
  })

  it('reports one for re-encryption even under the current kid', () => {
    expect(adapter.needsReEncrypt(legacyCiphertext('secret', KEY_A, 'k1', ctx))).toBe(true)
  })

  it('does not report a current ciphertext', async () => {
    expect(adapter.needsReEncrypt(await adapter.encrypt('secret', ctx))).toBe(false)
  })

  it('binds the kid, so one master key under two kids is two keys', async () => {
    const underK1 = await new AuthAesGcmDataAtRest({ kid: 'k1', masterKey: KEY_A }).encrypt('secret', ctx)
    const relabelled = underK1.replace('$k1$', '$k2$')
    const underK2 = new AuthAesGcmDataAtRest({ kid: 'k2', masterKey: KEY_A })
    await expect(underK2.decrypt(relabelled, ctx)).rejects.toThrow()
  })

  it('refuses an algorithm it does not know', async () => {
    const encrypted = await adapter.encrypt('secret', ctx)
    const [, kid, iv, tag, body] = parts(encrypted)
    await expect(adapter.decrypt(`aes-256-gcm.v3$${kid}$${iv}$${tag}$${body}`, ctx)).rejects.toThrow()
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
    for (const value of ['naïve', '🦆🦆🦆', '中文', 'café', 'a\u0000b']) {
      expect(await adapter.decrypt(await adapter.encrypt(value, ctx), ctx)).toBe(value)
    }
  })

  it('round-trips a value whose envelope is larger than the plaintext cap', async () => {
    // `decrypt` used to cap the ENVELOPE at the cap `encrypt` puts on the PLAINTEXT, and base64
    // expands by a third: anything over about 786,000 characters was written and then refused by
    // every read of itself.
    const big = 'x'.repeat(1_000_000)
    const encrypted = await adapter.encrypt(big, ctx)
    expect(encrypted.length).toBeGreaterThan(1_048_576)
    expect(await adapter.decrypt(encrypted, ctx)).toBe(big)
  })

  it('round-trips the largest plaintext it accepts', async () => {
    const largest = 'x'.repeat(1_048_576)
    expect(await adapter.decrypt(await adapter.encrypt(largest, ctx), ctx)).toBe(largest)
  })

  it('still refuses an envelope past what any accepted plaintext could produce', async () => {
    await expect(adapter.decrypt(`aes-256-gcm$k1$a$b$${'c'.repeat(4_200_000)}`, ctx)).rejects.toMatchObject({
      code: 'AUTH_INVALID_PARAMETERS',
    })
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
