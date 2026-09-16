'use client'

import { cn } from '@gentleduck/libs/cn'
import { Button } from '@gentleduck/registry-ui/button'
import { Field, FieldDescription, FieldGroup, FieldLabel } from '@gentleduck/registry-ui/field'
import { Input } from '@gentleduck/registry-ui/input'
import { Textarea } from '@gentleduck/registry-ui/textarea'
import { Loader2, Play, ScanSearch } from 'lucide-react'
import React from 'react'
import type { Explain } from '../../../core/explain'
import { iamNarrowAttributes } from '../../../shared/attributes'
import { safeParseJson } from '../../lib/format'
import { isDevtoolsAllowed } from '../../lib/guard'
import type { IamIDecisionInput, IamIDevtoolsEngine } from '../../lib/types'
import {
  IamV2Alert,
  IamV2Chip,
  IamV2Empty,
  IamV2Hint,
  IamV2PaneBody,
  IamV2PaneHeader,
  IamV2Root,
  IamV2Section,
  IamV2Split,
} from '../components/chrome'
import { IamV2Json } from '../components/json-view'
import { IAM_V2_ACTION, IAM_V2_MONO, IAM_V2_RESOURCE, iamV2Decision } from '../lib/tone'
import { IamTraceTreeV2 } from './trace'

/** The environment is a free-form record, so it only has to be a non-null, non-array object. */
function narrowRecord(value: unknown): Record<string, unknown> | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null
  const out: Record<string, unknown> = {}
  for (const [key, entry] of Object.entries(value)) out[key] = entry
  return out
}

const INITIAL: IamIDecisionInput = {
  action: '',
  attributesJson: '{}',
  environmentJson: '{}',
  resourceId: '',
  resourceType: '',
  scope: '',
  subjectId: '',
}

/** A labelled control. duck-ui's `Field` wired to the id the input carries. */
function Box({ children, id, label }: { children: React.ReactNode; id: string; label: string }) {
  return (
    <Field className="gap-1.5">
      <FieldLabel className="text-[0.6875rem] text-muted-foreground uppercase tracking-wider" htmlFor={id}>
        {label}
      </FieldLabel>
      {children}
    </Field>
  )
}

/**
 * Runs an ad-hoc check through `engine.explain()` and renders the trace with {@link IamTraceTreeV2}.
 * The JSON boxes are parsed on submit, and parse errors are rendered rather than thrown.
 */
export function IamDecisionInspectorV2({
  defaults,
  engine,
}: {
  defaults?: Partial<IamIDecisionInput>
  engine: IamIDevtoolsEngine
}) {
  const [input, setInput] = React.useState<IamIDecisionInput>({ ...INITIAL, ...defaults })
  const [result, setResult] = React.useState<Explain.IResult | null>(null)
  const [error, setError] = React.useState<string | null>(null)
  const [pending, setPending] = React.useState(false)
  const fieldId = React.useId()

  // SECURITY: guarded here too, since the panel is exported alone and `engine.explain` answers for any subject.
  // Below every hook so hook order is stable.
  if (!isDevtoolsAllowed(engine)) return null

  const update = (patch: Partial<IamIDecisionInput>) => setInput((state) => ({ ...state, ...patch }))

  // Cmd/Ctrl+Enter evaluates; plain Enter stays a newline in the JSON textareas.
  const onFormKeyDown = (event: React.KeyboardEvent) => {
    if (event.key !== 'Enter' || !(event.metaKey || event.ctrlKey)) return
    event.preventDefault()
    if (!pending) void run()
  }

  async function run() {
    setError(null)
    setPending(true)
    try {
      const attrs = safeParseJson(input.attributesJson)
      const env = safeParseJson(input.environmentJson)
      if (attrs.error) throw new Error(`attributes JSON: ${attrs.error}`)
      if (env.error) throw new Error(`environment JSON: ${env.error}`)
      // Valid JSON is not necessarily an attribute bag, so narrow before the engine sees it.
      const attributes = attrs.value === undefined ? {} : iamNarrowAttributes(attrs.value)
      if (attributes === null) throw new Error('attributes JSON: expected an object of scalar values')
      const environment = env.value === undefined ? {} : narrowRecord(env.value)
      if (environment === null) throw new Error('environment JSON: expected an object')
      // NOTE: pass `scope` positionally; nothing reads it from the environment bag, so it would show a false deny.
      const trace = await engine.explain(
        input.subjectId,
        input.action,
        { attributes, id: input.resourceId || undefined, type: input.resourceType },
        environment,
        input.scope || undefined,
      )
      setResult(trace)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setPending(false)
    }
  }

  return (
    <IamV2Root className="flex-1">
      <IamV2Split
        detail={
          error ? (
            <div className="p-3">
              <IamV2Alert tone="error">{error}</IamV2Alert>
            </div>
          ) : !result ? (
            <div className="flex min-h-0 flex-1 items-center justify-center p-6">
              <IamV2Empty
                description="Fill in a subject, an action and a resource, then evaluate to see every rule that voted."
                icon={<ScanSearch />}
                title="No evaluation yet"
              />
            </div>
          ) : (
            <>
              <div className="flex shrink-0 flex-wrap items-center gap-2 border-border border-b bg-card px-3 py-2">
                <IamV2Chip tone={iamV2Decision(result.decision.allowed)}>
                  {result.decision.allowed ? 'allow' : 'deny'}
                </IamV2Chip>
                <code className={cn(IAM_V2_MONO, IAM_V2_ACTION)}>{input.action || '—'}</code>
                <span className="text-muted-foreground text-xs">on</span>
                <code className={cn(IAM_V2_MONO, IAM_V2_RESOURCE)}>{input.resourceType || '—'}</code>
                <span className="ms-auto text-[0.6875rem] text-muted-foreground">subject {input.subjectId || '—'}</span>
              </div>
              <IamV2PaneBody>
                <IamV2Section title="Reason">
                  <p className="text-muted-foreground text-xs leading-relaxed">{result.summary}</p>
                </IamV2Section>
                <IamV2Section title="Trace">
                  <IamTraceTreeV2 result={result} />
                </IamV2Section>
                <IamV2Section defaultOpen={false} title="Raw result">
                  <IamV2Json data={result} />
                </IamV2Section>
              </IamV2PaneBody>
            </>
          )
        }
        list={
          <>
            <IamV2PaneHeader actions={<IamV2Hint keys={['⌘', '↵']}>evaluate</IamV2Hint>} title="Request" />
            <IamV2PaneBody className="gap-3">
              {/* One `FieldGroup` so the form shares duck-ui's field spacing and a single shortcut handler. */}
              <FieldGroup className="gap-3" onKeyDown={onFormKeyDown}>
                <Box id={`${fieldId}-subject`} label="subject id">
                  <Input
                    className="h-8 font-mono text-xs"
                    id={`${fieldId}-subject`}
                    onChange={(e) => update({ subjectId: e.target.value })}
                    placeholder="user-1"
                    value={input.subjectId}
                  />
                </Box>
                <div className="grid grid-cols-2 gap-3">
                  <Box id={`${fieldId}-action`} label="action">
                    <Input
                      className="h-8 font-mono text-xs"
                      id={`${fieldId}-action`}
                      onChange={(e) => update({ action: e.target.value })}
                      placeholder="read"
                      value={input.action}
                    />
                  </Box>
                  <Box id={`${fieldId}-scope`} label="scope">
                    <Input
                      className="h-8 font-mono text-xs"
                      id={`${fieldId}-scope`}
                      onChange={(e) => update({ scope: e.target.value })}
                      placeholder="org-acme"
                      value={input.scope}
                    />
                  </Box>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <Box id={`${fieldId}-rtype`} label="resource type">
                    <Input
                      className="h-8 font-mono text-xs"
                      id={`${fieldId}-rtype`}
                      onChange={(e) => update({ resourceType: e.target.value })}
                      placeholder="post"
                      value={input.resourceType}
                    />
                  </Box>
                  <Box id={`${fieldId}-rid`} label="resource id">
                    <Input
                      className="h-8 font-mono text-xs"
                      id={`${fieldId}-rid`}
                      onChange={(e) => update({ resourceId: e.target.value })}
                      placeholder="p-1"
                      value={input.resourceId}
                    />
                  </Box>
                </div>
                <Box id={`${fieldId}-attrs`} label="resource.attributes (JSON)">
                  <Textarea
                    className="font-mono text-xs"
                    id={`${fieldId}-attrs`}
                    onChange={(e) => update({ attributesJson: e.target.value })}
                    rows={4}
                    value={input.attributesJson}
                  />
                </Box>
                <Box id={`${fieldId}-env`} label="environment (JSON)">
                  <Textarea
                    className="font-mono text-xs"
                    id={`${fieldId}-env`}
                    onChange={(e) => update({ environmentJson: e.target.value })}
                    rows={3}
                    value={input.environmentJson}
                  />
                </Box>
                <Button className="h-8 gap-1.5" disabled={pending} onClick={() => void run()} size="sm">
                  {pending ? <Loader2 className="animate-spin" size={13} /> : <Play size={13} />}
                  {pending ? 'evaluating' : 'evaluate'}
                </Button>
                <FieldDescription className="text-[0.6875rem]">
                  Runs <code className="font-mono">engine.explain()</code>, not <code className="font-mono">can()</code>{' '}
                  - the reasoning is the point, not the boolean.
                </FieldDescription>
              </FieldGroup>
            </IamV2PaneBody>
          </>
        }
      />
    </IamV2Root>
  )
}
