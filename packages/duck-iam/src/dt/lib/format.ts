import { toErrorMessage } from '../../core/errors/normalize'
import type { Explain } from '../../core/explain'

/**
 * Renders an attribute value for the trace panel. Takes `unknown`, since the values are caller-controlled.
 * NOTE: never throws - it runs inside a React render, and `JSON.stringify` throws on cycles and `BigInt`.
 */
export function formatAttrValue(value: unknown): string {
  if (value === undefined) return '(undefined)'
  if (value === null) return 'null'
  if (typeof value === 'string') return stringify(value)
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  if (Array.isArray(value)) return `[${value.map((entry) => formatAttrValue(entry)).join(', ')}]`
  return stringify(value)
}

/** `JSON.stringify` with its two throwing cases turned into a rendered marker. */
function stringify(value: unknown): string {
  try {
    return JSON.stringify(value) ?? '(unserializable)'
  } catch {
    // Cyclic structure or a BigInt. Both are reachable from request attributes.
    return '(unserializable)'
  }
}

function pad(value: number, width = 2): string {
  return String(value).padStart(width, '0')
}

/** `14:03:11.482` - wall-clock, to line a decision up against an app log. */
export function formatClockTime(ts: number): string {
  const d = new Date(ts)
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`
}

/** Coarse relative age, meant to be re-rendered by the caller's own once-a-second ticker: `250ms ago` / `4s ago` / `3m ago` / `1h ago`. */
export function formatRelativeAge(ts: number, now: number): string {
  const ms = Math.max(0, now - ts)
  if (ms < 1000) return `${ms}ms ago`
  if (ms < 60_000) return `${Math.floor(ms / 1000)}s ago`
  if (ms < 3_600_000) return `${Math.floor(ms / 60_000)}m ago`
  return `${Math.floor(ms / 3_600_000)}h ago`
}

/**
 * Parses operator-typed JSON from a panel textarea.
 * NOTE: returns `unknown`; call sites must narrow before the value reaches the engine or adapter.
 *
 * @returns `{ value }` on success (`undefined` for blank input), `{ value: undefined, error }` on a parse failure.
 */
export function safeParseJson(raw: string): { value: unknown; error?: string } {
  const trimmed = raw.trim()
  if (!trimmed) return { value: undefined }
  try {
    return { value: JSON.parse(trimmed) }
  } catch (err) {
    return { error: toErrorMessage(err), value: undefined }
  }
}

/** Collapsed label for a trace node: `field operator expected` for a leaf, `LOGIC (n)` for a group. */
export function summarizeTrace(trace: Explain.Trace): string {
  if (trace.type === 'condition') {
    return `${trace.field} ${trace.operator} ${formatAttrValue(trace.expected)}`
  }
  const logic = trace.logic.toUpperCase()
  return `${logic} (${trace.children.length})`
}
