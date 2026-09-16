/**
 * One recorded authorization decision, flattened for the Flow panel.
 * Consumers can also record entries from their own instrumentation.
 */
export interface IamIFlowEntry {
  id: number
  ts: number
  subjectId: string
  action: string
  resource: string
  resourceId?: string
  scope?: string
  allowed: boolean
  durationMs?: number
  reason?: string
  decidingPolicy?: string
  decidingRule?: string
  environment?: Record<string, unknown>
}

type IFlowRecordInput = Omit<IamIFlowEntry, 'id' | 'ts'> & { ts?: number }

/**
 * Append-and-subscribe surface over the decision ring buffer.
 * `record` returns the entry with its assigned `id` and `ts`; `subscribe` returns its unsubscribe.
 */
export interface IamIFlowRecorder {
  record(entry: IFlowRecordInput): IamIFlowEntry
  list(): readonly IamIFlowEntry[]
  get(id: number): IamIFlowEntry | undefined
  clear(): void
  subscribe(listener: () => void): () => void
}

/** Options for {@link iamCreateFlowRecorder}. */
export interface IamIFlowRecorderOptions {
  /** Ring-buffer capacity. Must be a positive integer; defaults to 250. */
  bufferSize?: number
}

const DEFAULT_BUFFER = 250

/**
 * Builds the in-memory decision log the Flow panel renders; bind `record` to the engine's `afterEvaluate` hook.
 * Keeps the last `bufferSize` entries in memory only and notifies subscribers on every write.
 *
 * @param options - `bufferSize` caps retained entries; must be a positive integer, defaults to 250.
 * @throws RangeError when `bufferSize` is not a positive integer.
 * @example
 * ```ts
 * const flow = iamCreateFlowRecorder({ bufferSize: 500 })
 * const engine = new IamEngine({
 *   adapter,
 *   hooks: {
 *     afterEvaluate: (req, res, ms) =>
 *       flow.record({
 *         action: req.action,
 *         allowed: res.allowed,
 *         durationMs: ms,
 *         resource: req.resource.type,
 *         subjectId: req.subject.id,
 *       }),
 *   },
 * })
 * <IamDevtools engine={engine} flow={flow} />
 * ```
 */
export function iamCreateFlowRecorder(options: IamIFlowRecorderOptions = {}): IamIFlowRecorder {
  const bufferSize = options.bufferSize ?? DEFAULT_BUFFER
  // NaN/Infinity would disable the trim (unbounded growth); a negative would throw inside `record()`,
  // where `safeHookCall` swallows it.
  if (!Number.isInteger(bufferSize) || bufferSize < 1) {
    throw new RangeError(`[@gentleduck/iam:dt:flow] bufferSize must be a positive integer (got ${String(bufferSize)})`)
  }
  let nextId = 1
  let buffer: IamIFlowEntry[] = []
  const listeners = new Set<() => void>()

  function notify() {
    for (const fn of listeners) {
      try {
        fn()
      } catch (err) {
        // Devtools-only, so console is the whole error channel.
        console.error('[@gentleduck/iam:dt:flow] listener threw - continuing', err)
      }
    }
  }

  return {
    record(input) {
      const entry: IamIFlowEntry = {
        id: nextId++,
        ts: input.ts ?? Date.now(),
        subjectId: input.subjectId,
        action: input.action,
        resource: input.resource,
        resourceId: input.resourceId,
        scope: input.scope,
        allowed: input.allowed,
        durationMs: input.durationMs,
        reason: input.reason,
        decidingPolicy: input.decidingPolicy,
        decidingRule: input.decidingRule,
        environment: input.environment,
      }
      buffer.unshift(entry)
      if (buffer.length > bufferSize) buffer.length = bufferSize
      notify()
      return entry
    },
    list() {
      // A copy: `readonly` erases at runtime, so the live array would let callers mutate the buffer.
      return buffer.slice()
    },
    get(id) {
      return buffer.find((e) => e.id === id)
    },
    clear() {
      buffer = []
      notify()
    },
    subscribe(fn) {
      listeners.add(fn)
      return () => {
        listeners.delete(fn)
      }
    },
  }
}
