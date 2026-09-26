import React from 'react'
import { toErrorMessage } from '../../core/errors/normalize'
import type { Explain } from '../../core/explain'
import { iamNarrowAttributes } from '../../shared/attributes'
import { safeParseJson } from './format'
import type { IamIDecisionInput, IamIDevtoolsEngine } from './types'

/** The Decision Inspector's blank form state. */
const INITIAL: IamIDecisionInput = {
  subjectId: '',
  action: '',
  resourceType: '',
  resourceId: '',
  attributesJson: '{}',
  environmentJson: '{}',
  scope: '',
}

/** Narrows parsed JSON to a plain object (not `null`, not an array) for the free-form environment bag. */
function narrowEnvironment(value: unknown): Record<string, unknown> | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null
  const out: Record<string, unknown> = {}
  for (const [key, entry] of Object.entries(value)) out[key] = entry
  return out
}

/**
 * Validates a Decision Inspector form and runs `engine.explain()`.
 * NOTE: `scope` is the 5th positional argument; the engine never reads `environment.scope`.
 */
async function runDecisionCheck(
  engine: IamIDevtoolsEngine,
  input: IamIDecisionInput,
): Promise<{ trace: Explain.IResult } | { error: string }> {
  try {
    const attrs = safeParseJson(input.attributesJson)
    const env = safeParseJson(input.environmentJson)
    if (attrs.error) return { error: `attributes JSON: ${attrs.error}` }
    if (env.error) return { error: `environment JSON: ${env.error}` }
    // Valid JSON is not necessarily an attribute bag (`[1,2]` parses too), so narrow it.
    const attributes = attrs.value === undefined ? {} : iamNarrowAttributes(attrs.value)
    if (attributes === null) return { error: 'attributes JSON: expected an object of scalar values' }
    const environment = env.value === undefined ? {} : narrowEnvironment(env.value)
    if (environment === null) return { error: 'environment JSON: expected an object' }
    const resource = { type: input.resourceType, id: input.resourceId || undefined, attributes }
    const trace = await engine.explain(input.subjectId, input.action, resource, environment, input.scope || undefined)
    return { trace }
  } catch (err) {
    return { error: toErrorMessage(err) }
  }
}

/**
 * Shared state behind the Decision Inspector (in both v1 and v2): the form, its JSON validation, and the
 * `engine.explain()` call. Each version only differs in how it renders the result.
 */
export function useIamDecisionInspector(engine: IamIDevtoolsEngine, defaults?: Partial<IamIDecisionInput>) {
  const [input, setInput] = React.useState<IamIDecisionInput>({ ...INITIAL, ...defaults })
  const [result, setResult] = React.useState<Explain.IResult | null>(null)
  const [error, setError] = React.useState<string | null>(null)
  const [pending, setPending] = React.useState(false)

  const update = (patch: Partial<IamIDecisionInput>) => setInput((s) => ({ ...s, ...patch }))

  async function run() {
    setError(null)
    setPending(true)
    const outcome = await runDecisionCheck(engine, input)
    if ('error' in outcome) setError(outcome.error)
    else setResult(outcome.trace)
    setPending(false)
  }

  return { error, input, pending, result, run, update }
}
