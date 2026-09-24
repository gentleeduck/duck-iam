import { describe, expect, it } from 'vitest'
import { hasIamErrorCode } from '../../../core/errors'
import { iamReadJsonBody } from '../index'

describe('iamReadJsonBody', () => {
  it('returns the parsed body on success', async () => {
    await expect(iamReadJsonBody(async () => ({ a: 1 }))).resolves.toEqual({ a: 1 })
  })

  it('converts a parse failure into a typed IAM_VALIDATION_FAILED, not the raw parser error', async () => {
    const err = await iamReadJsonBody(async () => {
      throw new SyntaxError('Unexpected token x in JSON at position 4')
    }).catch((e: unknown) => e)
    expect(hasIamErrorCode(err, 'IAM_VALIDATION_FAILED')).toBe(true)
    if (hasIamErrorCode(err, 'IAM_VALIDATION_FAILED')) expect(err.meta.issues).toEqual(['MALFORMED_JSON'])
  })

  it('never lets the raw parser message, which quotes caller-controlled bytes, reach the thrown error', async () => {
    const secret = 'attacker-controlled-secret-marker'
    const err = await iamReadJsonBody(async () => {
      throw new SyntaxError(`Unexpected token, ${secret}`)
    }).catch((e: unknown) => e)
    expect((err as Error).message).not.toContain(secret)
  })
})
