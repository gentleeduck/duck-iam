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

export interface IamIFlowRecorder {
  record(entry: IFlowRecordInput): IamIFlowEntry
  list(): readonly IamIFlowEntry[]
  get(id: number): IamIFlowEntry | undefined
  clear(): void
  subscribe(listener: () => void): () => void
}

export interface IamIFlowRecorderOptions {
  bufferSize?: number
}

const DEFAULT_BUFFER = 250

export function iamCreateFlowRecorder(options: IamIFlowRecorderOptions = {}): IamIFlowRecorder {
  const bufferSize = options.bufferSize ?? DEFAULT_BUFFER
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
      return buffer
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
