import React from 'react'
import type { Explain } from '../../core/explain'
import { iamNarrowAttributes } from '../../shared/attributes'
import { Spinner } from '../components/icons'
import { JsonTree } from '../components/json-tree'
import { DetailEmpty, Section, SplitView } from '../components/layout'
import { Alert, Badge, Button, Field, Input, TextArea } from '../components/ui'
import { safeParseJson } from '../lib/format'
import { isDevtoolsAllowed } from '../lib/guard'
import { useIamDevtoolsStyles } from '../lib/styles'
import type { IamIDecisionInput, IamIDevtoolsEngine } from '../lib/types'
import { IamTraceTree } from './trace-tree'

/** Narrows parsed JSON to a plain object (not `null`, not an array) for the free-form environment bag. */
function narrowRecord(value: unknown): Record<string, unknown> | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null
  const out: Record<string, unknown> = {}
  for (const [key, entry] of Object.entries(value)) out[key] = entry
  return out
}

const INITIAL: IamIDecisionInput = {
  subjectId: '',
  action: '',
  resourceType: '',
  resourceId: '',
  attributesJson: '{}',
  environmentJson: '{}',
  scope: '',
}

/**
 * Runs an ad-hoc `engine.explain()` and renders the trace via {@link IamTraceTree}.
 * Invalid JSON in the attribute or environment box is shown as an error instead of being sent.
 */
export function IamDecisionInspector({
  engine,
  defaults,
}: {
  engine: IamIDevtoolsEngine
  defaults?: Partial<IamIDecisionInput>
}) {
  useIamDevtoolsStyles()
  const [input, setInput] = React.useState<IamIDecisionInput>({ ...INITIAL, ...defaults })
  const [result, setResult] = React.useState<Explain.IResult | null>(null)
  const [error, setError] = React.useState<string | null>(null)
  const [pending, setPending] = React.useState(false)

  // SECURITY: each panel is exported on its own, so it runs the guard itself. Kept below every hook.
  if (!isDevtoolsAllowed(engine)) return null

  const update = (patch: Partial<IamIDecisionInput>) => setInput((s) => ({ ...s, ...patch }))

  async function run() {
    setError(null)
    setPending(true)
    try {
      const attrs = safeParseJson(input.attributesJson)
      const env = safeParseJson(input.environmentJson)
      if (attrs.error) throw new Error(`attributes JSON: ${attrs.error}`)
      if (env.error) throw new Error(`environment JSON: ${env.error}`)
      // Valid JSON is not necessarily an attribute bag (`[1,2]` parses too), so narrow it.
      const attributes = attrs.value === undefined ? {} : iamNarrowAttributes(attrs.value)
      if (attributes === null) throw new Error('attributes JSON: expected an object of scalar values')
      const environment = env.value === undefined ? {} : narrowRecord(env.value)
      if (environment === null) throw new Error('environment JSON: expected an object')
      const resource = { type: input.resourceType, id: input.resourceId || undefined, attributes }
      // NOTE: `scope` must be the 5th argument; the engine never reads `environment.scope`.
      const trace = await engine.explain(input.subjectId, input.action, resource, environment, input.scope || undefined)
      setResult(trace)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setPending(false)
    }
  }

  return (
    <SplitView
      left={
        <div className="iam-dt-listshell">
          <div className="iam-dt-listshell__head">
            <h3 className="iam-dt-listshell__title">Request</h3>
            <Button disabled={pending} onClick={run} variant="primary">
              {pending ? <Spinner size={10} /> : null}
              {pending ? 'running' : 'evaluate'}
            </Button>
          </div>
          <div className="iam-dt-pad iam-dt-col" style={{ overflow: 'auto' }}>
            <Field label="subject id">
              <Input
                onChange={(e) => update({ subjectId: e.target.value })}
                placeholder="user-1"
                value={input.subjectId}
              />
            </Field>
            <div className="iam-dt-grid-2">
              <Field label="action">
                <Input onChange={(e) => update({ action: e.target.value })} placeholder="read" value={input.action} />
              </Field>
              <Field label="scope">
                <Input onChange={(e) => update({ scope: e.target.value })} placeholder="org-acme" value={input.scope} />
              </Field>
            </div>
            <div className="iam-dt-grid-2">
              <Field label="resource type">
                <Input
                  onChange={(e) => update({ resourceType: e.target.value })}
                  placeholder="post"
                  value={input.resourceType}
                />
              </Field>
              <Field label="resource id">
                <Input
                  onChange={(e) => update({ resourceId: e.target.value })}
                  placeholder="p-1"
                  value={input.resourceId}
                />
              </Field>
            </div>
            <Field label="resource.attributes (JSON)">
              <TextArea
                onChange={(e) => update({ attributesJson: e.target.value })}
                rows={4}
                value={input.attributesJson}
              />
            </Field>
            <Field label="environment (JSON)">
              <TextArea
                onChange={(e) => update({ environmentJson: e.target.value })}
                rows={3}
                value={input.environmentJson}
              />
            </Field>
          </div>
        </div>
      }
      right={
        error ? (
          <Alert kind="error">{error}</Alert>
        ) : !result ? (
          <DetailEmpty message="Run an evaluation to see the trace." />
        ) : (
          <div className="iam-dt-detail">
            <div className="iam-dt-detail__head">
              <Badge tone={result.decision.allowed ? 'allow' : 'deny'}>
                {result.decision.allowed ? 'allow' : 'deny'}
              </Badge>
              <code className="iam-dt-action">{input.action}</code>
              <span className="iam-dt-mute">on</span>
              <code className="iam-dt-resource">{input.resourceType}</code>
              <span className="iam-dt-detail__meta">subject: {input.subjectId || '-'}</span>
            </div>
            <Section title="Reason">
              <p className="iam-dt-soft" style={{ fontSize: 11 }}>
                {result.summary}
              </p>
            </Section>
            <Section title="Trace">
              <IamTraceTree result={result} />
            </Section>
            <Section defaultOpen={false} title="Raw result">
              <JsonTree data={result} defaultOpen />
            </Section>
          </div>
        )
      }
    />
  )
}
