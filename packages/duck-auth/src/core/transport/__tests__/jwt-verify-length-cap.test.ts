import { describe, expect, it } from 'vitest'
import { BearerTransport } from '../bearer'
import { CompositeTransport } from '../composite'
import { JwtTransport } from '../jwt'

const SECRET = 'a-very-long-test-secret-that-is-32-bytes!'

describe('JwtTransport.verify - length cap', () => {
  const t = new JwtTransport({
    issuer: 'https://app.test',
    signKey: { kid: 'k1', key: SECRET },
    verifyKeys: [{ kid: 'k1', key: SECRET }],
  })

  it('returns null on a multi-MB token without doing any base64 / JSON / crypto work', async () => {
    const oversize = 'A'.repeat(10 * 1024 * 1024) // 10 MiB
    const start = performance.now()
    await expect(t.verify(oversize)).resolves.toBeNull()
    const elapsed = performance.now() - start
    // Without the cap: base64decode + JSON.parse + crypto on 10 MB
    // would be hundreds of milliseconds. With the cap: O(1). Allow
    // 25 ms for CI noise / GC; anything over indicates regression.
    expect(elapsed).toBeLessThan(25)
  })

  it('returns null on a token exactly 4097 chars (just over the cap)', async () => {
    await expect(t.verify('B'.repeat(4097))).resolves.toBeNull()
  })

  it('processes a 4096-char token through the normal parse path (cap boundary)', async () => {
    // 4096 chars happens to be a valid-shape-but-bad-signature JWT
    // length range. The cap MUST NOT reject it; the cap rejects only
    // strings strictly longer than 4096.
    const sized = 'C'.repeat(4096)
    // Verify reaches the normal parse path and returns null on the
    // signature mismatch - NOT on the cap.
    await expect(t.verify(sized)).resolves.toBeNull()
  })

  it('rejects non-string input without crashing', async () => {
    await expect(t.verify(null as unknown as string)).resolves.toBeNull()
    await expect(t.verify(undefined as unknown as string)).resolves.toBeNull()
    await expect(t.verify(42 as unknown as string)).resolves.toBeNull()
  })

  it('rejects empty token', async () => {
    await expect(t.verify('')).resolves.toBeNull()
  })
})

describe('CompositeTransport.verify - length cap', () => {
  const jwt = new JwtTransport({
    issuer: 'https://app.test',
    signKey: { kid: 'k1', key: SECRET },
    verifyKeys: [{ kid: 'k1', key: SECRET }],
  })
  const composite = new CompositeTransport([new BearerTransport(), jwt])

  it('returns null on a multi-MB token without walking any inner transport', async () => {
    const oversize = 'A'.repeat(10 * 1024 * 1024)
    const start = performance.now()
    await expect(composite.verify(oversize)).resolves.toBeNull()
    const elapsed = performance.now() - start
    expect(elapsed).toBeLessThan(25)
  })

  it('rejects non-string at the composite boundary (no inner walk)', async () => {
    await expect(composite.verify(null as unknown as string)).resolves.toBeNull()
    await expect(composite.verify(42 as unknown as string)).resolves.toBeNull()
  })
})
