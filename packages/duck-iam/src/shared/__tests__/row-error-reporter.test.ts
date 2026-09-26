import { describe, expect, it, vi } from 'vitest'
import { iamRowErrorReporter } from '../row-error-reporter'

describe('iamRowErrorReporter', () => {
  it('warns, tagged with the adapter name, when no handler is set', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    try {
      const report = iamRowErrorReporter('file', undefined)
      report(new Error('bad json'), 'row-1')
      expect(warn).toHaveBeenCalledTimes(1)
      expect(warn).toHaveBeenCalledWith('[@gentleduck/iam:file] dropped malformed row "row-1": bad json')
    } finally {
      warn.mockRestore()
    }
  })

  it('routes to the handler instead of warning when one is set', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const onPolicyError = vi.fn()
    try {
      const report = iamRowErrorReporter('redis', onPolicyError)
      const err = new Error('bad json')
      report(err, 'row-1')
      expect(onPolicyError).toHaveBeenCalledTimes(1)
      expect(onPolicyError).toHaveBeenCalledWith(err, { adapter: 'redis', rowId: 'row-1' })
      expect(warn).not.toHaveBeenCalled()
    } finally {
      warn.mockRestore()
    }
  })
})
