'use client'

import { Button } from '@gentleduck/registry-ui/button'
import { ButtonGroup } from '@gentleduck/registry-ui/button-group'
import { Field, FieldDescription, FieldGroup, FieldLabel } from '@gentleduck/registry-ui/field'
import { Input } from '@gentleduck/registry-ui/input'
import { Textarea } from '@gentleduck/registry-ui/textarea'
import { Save, Search, ShieldMinus, ShieldPlus, UserRound } from 'lucide-react'
import React from 'react'
import type { IamPrimitives } from '../../../core/types'
import { iamNarrowAttributes } from '../../../shared/attributes'
import { safeParseJson } from '../../lib/format'
import { isDevtoolsAllowed } from '../../lib/guard'
import type { IamIDevtoolsEngine } from '../../lib/types'
import {
  IamV2Alert,
  IamV2Avatar,
  IamV2Chip,
  IamV2Empty,
  IamV2Notice,
  IamV2PaneBody,
  IamV2PaneHeader,
  IamV2Root,
  IamV2Section,
  IamV2Split,
} from '../components/chrome'
import { IamV2Json } from '../components/json-view'
import { IAM_V2_MONO } from '../lib/tone'

/**
 * Inspects one subject - its attributes and its role assignments - and, unlike
 * every other v2 panel, edits them: assigning and revoking roles and saving
 * attributes through `engine.admin`.
 *
 * The panel that writes the most, and the reason `isDevtoolsAllowed` blocks by
 * default. Without an explicit development signal this would ship as a
 * role-assignment UI with no authorization in front of it, reachable straight
 * from the `./dt/v2` export.
 */
export function IamSubjectsPanelV2({ engine }: { engine: IamIDevtoolsEngine }) {
  const [subjectId, setSubjectId] = React.useState('')
  const [attrs, setAttrs] = React.useState<IamPrimitives.Attributes | null>(null)
  const [attrsDraft, setAttrsDraft] = React.useState('{}')
  const [roleId, setRoleId] = React.useState('')
  const [scope, setScope] = React.useState('')
  const [busy, setBusy] = React.useState(false)
  const [error, setError] = React.useState<string | null>(null)
  const [status, setStatus] = React.useState<string | null>(null)
  const fieldId = React.useId()

  // Below every hook. `engine` does not change identity across renders of a
  // mounted panel, so this cannot flip mid-life either.
  if (!isDevtoolsAllowed(engine)) return null

  /** Every mutation shares this frame: clear both messages, run, report. */
  async function attempt(what: () => Promise<string>) {
    setError(null)
    setStatus(null)
    setBusy(true)
    try {
      setStatus(await what())
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const load = () => {
    if (!subjectId) return setError('subject id required')
    return attempt(async () => {
      const loaded = await engine.admin.getAttributes(subjectId)
      setAttrs(loaded)
      setAttrsDraft(JSON.stringify(loaded, null, 2))
      return `loaded ${Object.keys(loaded).length} attributes`
    })
  }

  const saveAttrs = () => {
    const parsed = safeParseJson(attrsDraft)
    if (parsed.error) return setError(`attributes JSON: ${parsed.error}`)
    // Narrowed before it reaches the adapter: `setAttributes` writes whatever
    // it is handed, and this value came out of a textarea.
    const attributes = parsed.value === undefined ? {} : iamNarrowAttributes(parsed.value)
    if (attributes === null) return setError('attributes JSON: expected an object of scalar values')
    return attempt(async () => {
      await engine.admin.setAttributes(subjectId, attributes)
      setAttrs(attributes)
      return 'attributes saved'
    })
  }

  const assign = () => {
    if (!roleId) return setError('role id required')
    return attempt(async () => {
      await engine.admin.assignRole(subjectId, roleId, scope || undefined)
      return `assigned ${roleId}${scope ? ` @ ${scope}` : ''}`
    })
  }

  const revoke = () => {
    if (!roleId) return setError('role id required')
    return attempt(async () => {
      await engine.admin.revokeRole(subjectId, roleId, scope || undefined)
      return `revoked ${roleId}${scope ? ` @ ${scope}` : ''}`
    })
  }

  return (
    <IamV2Root className="flex-1">
      <IamV2Split
        detail={
          !subjectId ? (
            <div className="flex min-h-0 flex-1 items-center justify-center p-6">
              <IamV2Empty
                description="Enter a subject id on the left to read and edit its attributes and roles."
                icon={<UserRound />}
                title="No subject selected"
              />
            </div>
          ) : (
            <>
              <div className="flex shrink-0 flex-wrap items-center gap-2 border-border border-b bg-card px-3 py-2">
                <IamV2Avatar id={subjectId} />
                <code className={IAM_V2_MONO}>{subjectId}</code>
                {attrs && <IamV2Chip tone="info">{Object.keys(attrs).length} attributes</IamV2Chip>}
              </div>
              <IamV2PaneBody>
                <IamV2Section title="Attributes">
                  {attrs ? (
                    <IamV2Json data={attrs} />
                  ) : (
                    <p className="text-muted-foreground text-xs">Load the subject to read its attributes.</p>
                  )}
                </IamV2Section>
                <IamV2Section defaultOpen={false} title="Edit attributes (JSON)">
                  <div className="flex flex-col gap-2">
                    <Textarea
                      aria-label="Subject attributes as JSON"
                      className="font-mono text-xs"
                      onChange={(e) => setAttrsDraft(e.target.value)}
                      rows={10}
                      value={attrsDraft}
                    />
                    <Button
                      className="h-8 gap-1.5 self-start"
                      disabled={busy}
                      onClick={() => void saveAttrs()}
                      size="sm">
                      <Save size={13} />
                      save attributes
                    </Button>
                  </div>
                </IamV2Section>
                <IamV2Section defaultOpen={false} title="Role assignment">
                  <FieldGroup className="gap-3">
                    <div className="grid grid-cols-2 gap-3">
                      <Field className="gap-1.5">
                        <FieldLabel
                          className="text-[0.6875rem] text-muted-foreground uppercase tracking-wider"
                          htmlFor={`${fieldId}-role`}>
                          role id
                        </FieldLabel>
                        <Input
                          className="h-8 font-mono text-xs"
                          id={`${fieldId}-role`}
                          onChange={(e) => setRoleId(e.target.value)}
                          placeholder="editor"
                          value={roleId}
                        />
                      </Field>
                      <Field className="gap-1.5">
                        <FieldLabel
                          className="text-[0.6875rem] text-muted-foreground uppercase tracking-wider"
                          htmlFor={`${fieldId}-scope`}>
                          scope (optional)
                        </FieldLabel>
                        <Input
                          className="h-8 font-mono text-xs"
                          id={`${fieldId}-scope`}
                          onChange={(e) => setScope(e.target.value)}
                          placeholder="org-acme"
                          value={scope}
                        />
                      </Field>
                    </div>
                    <ButtonGroup aria-label="Role assignment" className="self-start">
                      <Button className="h-8 gap-1.5" disabled={busy} onClick={() => void assign()} size="sm">
                        <ShieldPlus size={13} />
                        assign
                      </Button>
                      <Button
                        className="h-8 gap-1.5"
                        disabled={busy}
                        onClick={() => void revoke()}
                        size="sm"
                        variant="destructive">
                        <ShieldMinus size={13} />
                        revoke
                      </Button>
                    </ButtonGroup>
                    <FieldDescription className="text-[0.6875rem]">
                      Writes straight through <code className="font-mono">engine.admin</code> - the reason this panel is
                      blocked outside development.
                    </FieldDescription>
                  </FieldGroup>
                </IamV2Section>
              </IamV2PaneBody>
            </>
          )
        }
        list={
          <>
            <IamV2PaneHeader title="Lookup" />
            <IamV2PaneBody className="gap-3">
              <Field className="gap-1.5">
                <FieldLabel
                  className="text-[0.6875rem] text-muted-foreground uppercase tracking-wider"
                  htmlFor={`${fieldId}-subject`}>
                  subject id
                </FieldLabel>
                <Input
                  className="h-8 font-mono text-xs"
                  id={`${fieldId}-subject`}
                  onChange={(e) => setSubjectId(e.target.value)}
                  placeholder="user-1"
                  value={subjectId}
                />
              </Field>
              <Button className="h-8 gap-1.5" disabled={busy} onClick={() => void load()} size="sm">
                <Search size={13} />
                load subject
              </Button>
              {error && <IamV2Alert tone="error">{error}</IamV2Alert>}
              {status && <IamV2Alert tone="success">{status}</IamV2Alert>}
              {!error && !status && !subjectId && (
                <IamV2Notice title="This panel writes" tone="info">
                  Assigning a role or saving attributes changes the live model through the adapter behind{' '}
                  <code className="font-mono">engine.admin</code>.
                </IamV2Notice>
              )}
            </IamV2PaneBody>
          </>
        }
      />
    </IamV2Root>
  )
}
