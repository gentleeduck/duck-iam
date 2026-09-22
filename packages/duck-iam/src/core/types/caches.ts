/** Per-Engine evaluation caches; evaluators accept `caches?` to scope regex/path caches per instance. */
export interface IamEvalCaches {
  /** Compiled-regex LRU shared by the `matches` operator. */
  regex: Map<string, RegExp>
  /** Resolved dot-path segment FIFO. */
  path: Map<string, string[] | null>
}

/** Creates a fresh, empty {@link IamEvalCaches}. */
export function iamCreateEvalCaches(): IamEvalCaches {
  return { regex: new Map(), path: new Map() }
}
