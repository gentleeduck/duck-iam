/**
 * One recorded authorization decision, as the Flow panel renders it: the
 * request that was asked, the answer, and - when the engine explained itself -
 * which policy and rule decided it. Flattened out of the engine's own request /
 * result types so the panel does not have to reach through nested objects, and
 * so a consumer can record from their own instrumentation.
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
 * The append-and-subscribe surface over the decision ring buffer. `record`
 * returns the stamped entry (with the `id` and `ts` it assigned) so a caller
 * can correlate; `subscribe` returns its own unsubscribe.
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
 * Builds the in-memory decision log the devtools Flow panel renders.
 *
 * Bind it to the engine's `afterEvaluate` hook and the panel fills itself; the
 * recorder holds the last `bufferSize` decisions in a ring buffer and notifies
 * subscribers on every write. Nothing is persisted and nothing leaves the
 * process - it is a debugging surface, and `IamDevtools` refuses to mount it
 * outside an explicit development build (see {@link isDevtoolsAllowed}).
 *
 * @param options - `bufferSize` caps retained entries; must be a positive integer, defaults to 250.
 * @returns A recorder exposing `record`, `list`, `get`, `clear` and `subscribe`.
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
  // Same discipline as `iamCreateMetricsAggregator`'s `sampleSize`. Unchecked,
  // NaN/Infinity make the `> bufferSize` trim permanently false so the ring
  // buffer grows without bound, and a negative throws `Invalid array length`
  // from inside `record()` - which `safeHookCall` swallows, leaving a recorder
  // that silently records nothing.
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
        // Devtools-only, so console is the whole error channel - no
        // operator-facing callback is needed.
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
      // The declared type is `readonly`, which erases: returning the live array
      // let a caller push into the recorder's own buffer.
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
