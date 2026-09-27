'use client'

import { cn } from '@gentleduck/libs/cn'
import { Button } from '@gentleduck/registry-ui/button'
import { FieldDescription, FieldGroup } from '@gentleduck/registry-ui/field'
import { Textarea } from '@gentleduck/registry-ui/textarea'
import { Loader2, Play, ScanSearch } from 'lucide-react'
import React from 'react'
import { useIamDecisionInspector } from '../../lib/decision'
import { isDevtoolsAllowed } from '../../lib/guard'
import type { IamIDecisionInput, IamIDevtoolsEngine } from '../../lib/types'
import {
  IamV2Alert,
  IamV2Chip,
  IamV2Empty,
  IamV2FieldBox,
  IamV2Hint,
  IamV2PaneBody,
  IamV2PaneHeader,
  IamV2Root,
  IamV2Section,
  IamV2Split,
  IamV2TextField,
} from '../components/chrome'
import { IamV2Json } from '../components/json-view'
import { IAM_V2_ACTION, IAM_V2_MONO, IAM_V2_RESOURCE, iamV2Decision } from '../lib/tone'
import { IamTraceTreeV2 } from './trace'

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
  const { error, input, pending, result, run, update } = useIamDecisionInspector(engine, defaults)
  const fieldId = React.useId()

  // SECURITY: guarded here too, since the panel is exported alone and `engine.explain` answers for any subject.
  // Below every hook so hook order is stable.
  if (!isDevtoolsAllowed(engine)) return null

  // Cmd/Ctrl+Enter evaluates; plain Enter stays a newline in the JSON textareas.
  const onFormKeyDown = (event: React.KeyboardEvent) => {
    if (event.key !== 'Enter' || !(event.metaKey || event.ctrlKey)) return
    event.preventDefault()
    if (!pending) void run()
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
                <IamV2TextField
                  id={`${fieldId}-subject`}
                  label="subject id"
                  onChange={(value) => update({ subjectId: value })}
                  placeholder="user-1"
                  value={input.subjectId}
                />
                <div className="grid grid-cols-2 gap-3">
                  <IamV2TextField
                    id={`${fieldId}-action`}
                    label="action"
                    onChange={(value) => update({ action: value })}
                    placeholder="read"
                    value={input.action}
                  />
                  <IamV2TextField
                    id={`${fieldId}-scope`}
                    label="scope"
                    onChange={(value) => update({ scope: value })}
                    placeholder="org-acme"
                    value={input.scope}
                  />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <IamV2TextField
                    id={`${fieldId}-rtype`}
                    label="resource type"
                    onChange={(value) => update({ resourceType: value })}
                    placeholder="post"
                    value={input.resourceType}
                  />
                  <IamV2TextField
                    id={`${fieldId}-rid`}
                    label="resource id"
                    onChange={(value) => update({ resourceId: value })}
                    placeholder="p-1"
                    value={input.resourceId}
                  />
                </div>
                <IamV2FieldBox id={`${fieldId}-attrs`} label="resource.attributes (JSON)">
                  <Textarea
                    className="font-mono text-xs"
                    id={`${fieldId}-attrs`}
                    onChange={(e) => update({ attributesJson: e.target.value })}
                    rows={4}
                    value={input.attributesJson}
                  />
                </IamV2FieldBox>
                <IamV2FieldBox id={`${fieldId}-env`} label="environment (JSON)">
                  <Textarea
                    className="font-mono text-xs"
                    id={`${fieldId}-env`}
                    onChange={(e) => update({ environmentJson: e.target.value })}
                    rows={3}
                    value={input.environmentJson}
                  />
                </IamV2FieldBox>
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
