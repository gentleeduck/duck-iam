import type { Explain } from '../../core/explain'

/**
 * Renders an attribute value for the trace panel.
 *
 * Takes `unknown`, not `AttributeValue`: the values reaching it come from
 * `resolveConditionValue`, i.e. request attributes a caller controls, and
 * declaring the narrow type only bought an `as` on the recursive array call.
 *
 * Never throws. `JSON.stringify` does, on a self-referential value and on a
 * `BigInt`, and this runs inside a React render - so the throw took out the
 * panel, or the host app when there was no error boundary.
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

/**
 * Parses operator-typed JSON from a panel textarea.
 *
 * Returns `unknown`, not a caller-named `T`. It used to return `JSON.parse`'s
 * `any` under whatever type the call site asked for, and the parsed value was
 * then handed to `admin.setAttributes` - so a typo in the textarea reached the
 * adapter as an attribute bag of the wrong shape with nothing in between. Call
 * sites narrow with a real validator instead.
 *
 * @param raw - The textarea contents.
 * @returns `{ value }` on success, `{ value: undefined, error }` on a parse failure.
 * An empty or whitespace-only input is a success carrying `undefined`.
 */
export function safeParseJson(raw: string): { value: unknown; error?: string } {
  const trimmed = raw.trim()
  if (!trimmed) return { value: undefined }
  try {
    return { value: JSON.parse(trimmed) }
  } catch (err) {
    return { error: err instanceof Error ? err.message : String(err), value: undefined }
  }
}

/**
 * One-line summary of a trace node, used as the collapsed label in the tree.
 *
 * @param trace - The condition leaf or logic group to summarise.
 * @returns `field operator expected` for a leaf, `LOGIC (n)` for a group.
 */
export function summarizeTrace(trace: Explain.Trace): string {
  if (trace.type === 'condition') {
    return `${trace.field} ${trace.operator} ${formatAttrValue(trace.expected)}`
  }
  const logic = trace.logic.toUpperCase()
  return `${logic} (${trace.children.length})`
}
