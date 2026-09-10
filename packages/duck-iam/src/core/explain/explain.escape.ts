/**
 * Replace `& < > " '` with their HTML entities.
 * SECURITY: explain summaries and condition leaves carry policy names and request attributes verbatim, so any
 * consumer rendering a trace into a debug panel must pass them through here first.
 *
 * @returns HTML-safe escaped string.
 */
export function iamEscapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}
