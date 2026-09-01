import type { Explain } from '../../core/explain'
import type { IamPrimitives } from '../../core/types'

export function formatAttrValue(value: IamPrimitives.AttributeValue | undefined): string {
  if (value === undefined) return '(undefined)'
  if (value === null) return 'null'
  if (typeof value === 'string') return JSON.stringify(value)
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  if (Array.isArray(value))
    return `[${value.map((v) => formatAttrValue(v as IamPrimitives.AttributeValue)).join(', ')}]`
  return JSON.stringify(value)
}

export function safeParseJson<T = unknown>(raw: string, fallback: T): { value: T; error?: string } {
  const trimmed = raw.trim()
  if (!trimmed) return { value: fallback }
  try {
    return { value: JSON.parse(trimmed) as T }
  } catch (err) {
    return { value: fallback, error: err instanceof Error ? err.message : String(err) }
  }
}

export function summarizeTrace(trace: Explain.Trace): string {
  if (trace.type === 'condition') {
    return `${trace.field} ${trace.operator} ${formatAttrValue(trace.expected)}`
  }
  const logic = trace.logic.toUpperCase()
  return `${logic} (${trace.children.length})`
}
