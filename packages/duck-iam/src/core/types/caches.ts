/**
 * DEBT-6 / SEC-050: per-Engine evaluation caches.
 *
 * Threaded through every evaluator function so an Engine instance can own
 * its own regex + path caches instead of sharing module-globals with every
 * other Engine in the process.
 *
 * Backward compatibility: every consumer accepts `caches?` as the last
 * optional parameter. When omitted, the evaluator falls back to the
 * process-wide default caches (`regexCache` and `pathCache` exported from
 * `core/conditions/conditions.libs` and `core/resolve/resolve`). Existing
 * code paths that called `evaluate(...)`, `resolve(...)`, etc. directly
 * keep working unchanged.
 *
 * @author wildduck2 <https://github.com/wildduck2>
 */
export interface IEvalCaches {
  /** Compiled-regex LRU shared by the `matches` operator. */
  regex: Map<string, RegExp>
  /** Resolved dot-path segment FIFO. */
  path: Map<string, string[] | null>
}

/**
 * Construct a fresh pair of evaluation caches. Engine instances call this
 * once at construction and pass the result down on every authorize call.
 *
 * @returns A new {@link IEvalCaches} with empty maps.
 */
export function createEvalCaches(): IEvalCaches {
  return { regex: new Map(), path: new Map() }
}
