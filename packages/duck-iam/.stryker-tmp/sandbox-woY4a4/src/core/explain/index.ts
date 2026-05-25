// @ts-nocheck
export { explainEvaluation } from './explain'
export type { Explain } from './explain.types'

/**
 * Escape a value-derived string for safe inclusion in HTML.
 *
 * `Explain.IResult.summary` and condition-leaf `actual` / `expected` strings
 * carry operator-supplied policy names and request-attribute values verbatim.
 * If a consumer renders the explain trace into a debug panel, run those
 * untrusted strings through this helper first. Returns the same input with
 * `& < > " '` replaced by their HTML entities.
 *
 * @param s - Untrusted string from explain output.
 * @returns HTML-safe escaped string.
 */
export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}
