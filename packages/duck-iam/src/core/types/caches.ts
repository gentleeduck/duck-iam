/** Per-Engine evaluation caches; evaluators accept `caches?` to scope regex/path caches per instance. */
export interface IEvalCaches {
  /** Compiled-regex LRU shared by the `matches` operator. */
  regex: Map<string, RegExp>
  /** Resolved dot-path segment FIFO. */
  path: Map<string, string[] | null>
}

/**
 * Construct a fresh pair of evaluation caches.
 *
 * @returns A new {@link IEvalCaches} with empty maps.
 */
export function createEvalCaches(): IEvalCaches {
  return { regex: new Map(), path: new Map() }
}
