import { describe, expect, it } from 'vitest'
import type { Explain } from '../../core/explain'
import { formatAttrValue, safeParseJson, summarizeTrace } from '../lib/format'

function leaf(over: Partial<Explain.ILeafTrace> = {}): Explain.ILeafTrace {
  return {
    actual: 'u1',
    expected: 'u1',
    field: 'subject.id',
    operator: 'eq',
    result: true,
    type: 'condition',
    ...over,
  }
}

describe('formatAttrValue', () => {
  it('distinguishes undefined from null', () => {
    expect(formatAttrValue(undefined)).toBe('(undefined)')
    expect(formatAttrValue(null)).toBe('null')
  })

  it('quotes strings so empty and whitespace values stay visible', () => {
    expect(formatAttrValue('abc')).toBe('"abc"')
    expect(formatAttrValue('')).toBe('""')
    expect(formatAttrValue(' ')).toBe('" "')
  })

  it('escapes quotes inside strings', () => {
    expect(formatAttrValue('a"b')).toBe('"a\\"b"')
  })

  it('renders numbers and booleans unquoted', () => {
    expect(formatAttrValue(0)).toBe('0')
    expect(formatAttrValue(-1.5)).toBe('-1.5')
    expect(formatAttrValue(false)).toBe('false')
    expect(formatAttrValue(true)).toBe('true')
  })

  it('renders arrays with each element formatted', () => {
    expect(formatAttrValue(['a', 1, true])).toBe('["a", 1, true]')
    expect(formatAttrValue([])).toBe('[]')
  })

  it('formats nested arrays recursively', () => {
    expect(formatAttrValue([['a'], ['b']])).toBe('[["a"], ["b"]]')
  })
})

describe('safeParseJson', () => {
  // No `fallback` parameter and no caller-named `T` any more: it returned
  // `JSON.parse`'s `any` under whatever type the call site asked for, and the
  // value went on to `admin.setAttributes`. Call sites narrow it now.
  it('returns the parsed value with no error', () => {
    expect(safeParseJson('{"a":1}')).toEqual({ value: { a: 1 } })
  })

  it('returns undefined with no error for empty or whitespace input', () => {
    expect(safeParseJson('')).toEqual({ value: undefined })
    expect(safeParseJson('   \n ')).toEqual({ value: undefined })
  })

  it('returns an error message and no value for malformed input', () => {
    const out = safeParseJson('{nope')
    expect(out.value).toBeUndefined()
    expect(typeof out.error).toBe('string')
    expect(out.error).not.toBe('')
  })

  it('parses bare JSON scalars, which is why the call site must narrow', () => {
    expect(safeParseJson('null')).toEqual({ value: null })
    expect(safeParseJson('7')).toEqual({ value: 7 })
    expect(safeParseJson('"hello"')).toEqual({ value: 'hello' })
    expect(safeParseJson('[1,2]')).toEqual({ value: [1, 2] })
  })
})

describe('summarizeTrace', () => {
  it('renders a condition leaf as "field operator expected"', () => {
    expect(summarizeTrace(leaf({ expected: 'u1', field: 'subject.id', operator: 'eq' }))).toBe('subject.id eq "u1"')
  })

  it('formats the expected value through formatAttrValue', () => {
    expect(summarizeTrace(leaf({ expected: ['a', 'b'], operator: 'in' }))).toBe('subject.id in ["a", "b"]')
    expect(summarizeTrace(leaf({ expected: null }))).toBe('subject.id eq null')
  })

  it('renders a group as uppercased logic plus its direct child count', () => {
    const group: Explain.IGroupTrace = {
      children: [leaf(), leaf()],
      logic: 'all',
      result: false,
      type: 'group',
    }
    expect(summarizeTrace(group)).toBe('ALL (2)')
  })

  it('counts only direct children, not the whole subtree', () => {
    const nested: Explain.IGroupTrace = {
      children: [{ children: [leaf(), leaf()], logic: 'all', result: true, type: 'group' }],
      logic: 'any',
      result: true,
      type: 'group',
    }
    expect(summarizeTrace(nested)).toBe('ANY (1)')
  })

  it('renders an empty group as (0)', () => {
    const empty: Explain.IGroupTrace = { children: [], logic: 'none', result: true, type: 'group' }
    expect(summarizeTrace(empty)).toBe('NONE (0)')
  })
})
