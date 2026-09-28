import { describe, expect, it, vi } from 'vitest'
import { BearerTransport } from '../bearer.transport'
import { CompositeTransport } from '../composite.transport'
import { JwtTransport } from '../jwt.transport'

const SECRET = 'a-very-long-test-secret-that-is-32-bytes!'

describe('JwtTransport.verify - length cap', () => {
  const t = new JwtTransport({
    issuer: 'https://app.test',
    signKey: { kid: 'k1', key: SECRET },
    verifyKeys: [{ kid: 'k1', key: SECRET }],
  })

  const refused = (reason: string) => expect.objectContaining({ code: 'AUTH_JWT_INVALID', meta: { reason } })
  const AT_THE_CAP = 'token is empty or over the 4096-character cap'

  it('refuses a multi-MB token at the cap, before any base64, JSON or crypto work', async () => {
    // Three parts, so without the cap it would reach the header decode.
    const half = 'A'.repeat(5 * 1024 * 1024)
    const parse = vi.spyOn(JSON, 'parse')
    try {
      await expect(t.verify(`${half}.${half}.sig`)).rejects.toEqual(refused(AT_THE_CAP))
      expect(parse).not.toHaveBeenCalled()
    } finally {
      parse.mockRestore()
    }
  })

  it('refuses 4097 characters at the cap, and parses 4096', async () => {
    await expect(t.verify('B'.repeat(4097))).rejects.toEqual(refused(AT_THE_CAP))
    await expect(t.verify('C'.repeat(4096))).rejects.toEqual(refused('token is not a three-part JWS'))
  })

  it.each([null, undefined, 42])('refuses %o, which is not a token, without crashing', async (value) => {
    // @ts-expect-error: off-contract on purpose.
    await expect(t.verify(value)).rejects.toEqual(refused(AT_THE_CAP))
  })

  it('refuses an empty token', async () => {
    await expect(t.verify('')).rejects.toEqual(refused(AT_THE_CAP))
  })
})

describe('AuthCompositeTransport.verify - length cap', () => {
  const jwt = new JwtTransport({
    issuer: 'https://app.test',
    signKey: { kid: 'k1', key: SECRET },
    verifyKeys: [{ kid: 'k1', key: SECRET }],
  })
  const composite = new CompositeTransport([new BearerTransport(), jwt])

  it('refuses a multi-MB token without walking any inner transport', async () => {
    const inner = vi.spyOn(jwt, 'verify')
    await expect(composite.verify('A'.repeat(10 * 1024 * 1024))).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    expect(inner).not.toHaveBeenCalled()
    // A token under the cap is walked, so the spy can see a call.
    await expect(composite.verify('A'.repeat(100))).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
    expect(inner).toHaveBeenCalledOnce()
    inner.mockRestore()
  })

  it.each([null, 42])('refuses %o at the composite boundary, walking no inner transport', async (value) => {
    const inner = vi.spyOn(jwt, 'verify')
    try {
      // @ts-expect-error: off-contract on purpose.
      await expect(composite.verify(value)).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
      expect(inner).not.toHaveBeenCalled()
    } finally {
      inner.mockRestore()
    }
  })
})
