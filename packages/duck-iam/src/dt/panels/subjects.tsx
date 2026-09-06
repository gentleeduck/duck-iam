import React from 'react'
import type { IamPrimitives } from '../../core/types'
import { iamNarrowAttributes } from '../../shared/attributes'
import { JsonTree } from '../components/json-tree'
import { DetailEmpty, Section, SplitView } from '../components/layout'
import { Alert, Badge, Button, Field, Input, TextArea } from '../components/ui'
import { safeParseJson } from '../lib/format'
import { isDevtoolsAllowed } from '../lib/guard'
import { useIamDevtoolsStyles } from '../lib/styles'
import type { IamIDevtoolsEngine } from '../lib/types'

/**
 * Inspects one subject - its attributes and role assignments - and, unlike the
 * other panels, edits them: assigning and revoking roles and saving attributes
 * through `engine.admin`.
 *
 * The panel that writes the most, and the reason `isDevtoolsAllowed` blocks by
 * default: without an explicit development signal from both `NODE_ENV` and the
 * engine's own mode, this would ship as a role-assignment UI with no
 * authorization in front of it. It is not the *only* writer - `IamMetricsPanel`
 * calls `engine.stats.reset()` - and it is no longer the only panel carrying
 * the guard: every panel handed an engine calls it now, because the readers
 * leak the policy corpus and the role catalog through exactly the same
 * direct-import route this docblock describes.
 *
 * It calls that guard itself rather than relying on `IamDevtools` having called
 * it. `package.json` exports every panel individually under `./dt`, so
 * `import { IamSubjectsPanel } from '@gentleduck/iam/dt'` and rendering it is a
 * supported thing to do - and it put the one writing panel on screen with no
 * check anywhere in its path. The guard is idempotent and cheap, so running it
 * twice under `IamDevtools` costs nothing; running it zero times cost the whole
 * protection.
 */
export function IamSubjectsPanel({ engine }: { engine: IamIDevtoolsEngine }) {
  useIamDevtoolsStyles()
  const [subjectId, setSubjectId] = React.useState('')
  const [attrs, setAttrs] = React.useState<IamPrimitives.Attributes | null>(null)
  const [attrsDraft, setAttrsDraft] = React.useState('{}')
  const [roleId, setRoleId] = React.useState('')
  const [scope, setScope] = React.useState('')
  const [busy, setBusy] = React.useState(false)
  const [error, setError] = React.useState<string | null>(null)
  const [status, setStatus] = React.useState<string | null>(null)

  // Below every hook, so the hook order is the same on both branches. `engine`
  // does not change identity across renders of a mounted panel, so this cannot
  // flip mid-life either.
  if (!isDevtoolsAllowed(engine)) return null

  async function load() {
    setError(null)
    setStatus(null)
    if (!subjectId) return setError('subject id required')
    setBusy(true)
    try {
      const a = await engine.admin.getAttributes(subjectId)
      setAttrs(a)
      setAttrsDraft(JSON.stringify(a, null, 2))
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  async function saveAttrs() {
    setError(null)
    setStatus(null)
    const parsed = safeParseJson(attrsDraft)
    if (parsed.error) return setError(`attributes JSON: ${parsed.error}`)
    // Narrowed before it reaches the adapter: `setAttributes` writes whatever
    // it is handed, and this value came out of a textarea.
    const attributes = parsed.value === undefined ? {} : iamNarrowAttributes(parsed.value)
    if (attributes === null) return setError('attributes JSON: expected an object of scalar values')
    setBusy(true)
    try {
      await engine.admin.setAttributes(subjectId, attributes)
      setAttrs(attributes)
      setStatus('attributes saved')
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  async function assign() {
    setError(null)
    setStatus(null)
    if (!roleId) return setError('role id required')
    setBusy(true)
    try {
      await engine.admin.assignRole(subjectId, roleId, scope || undefined)
      setStatus(`assigned ${roleId}${scope ? ` @ ${scope}` : ''}`)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  async function revoke() {
    setError(null)
    setStatus(null)
    if (!roleId) return setError('role id required')
    setBusy(true)
    try {
      await engine.admin.revokeRole(subjectId, roleId, scope || undefined)
      setStatus(`revoked ${roleId}${scope ? ` @ ${scope}` : ''}`)
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <SplitView
      left={
        <div className="iam-dt-listshell">
          <div className="iam-dt-listshell__head">
            <h3 className="iam-dt-listshell__title">Lookup</h3>
          </div>
          <div className="iam-dt-pad iam-dt-col">
            <Field label="subject id">
              <Input onChange={(e) => setSubjectId(e.target.value)} placeholder="user-1" value={subjectId} />
            </Field>
            <Button disabled={busy} onClick={load} variant="primary">
              load
            </Button>
            {error && <Alert kind="error">{error}</Alert>}
            {status && <Alert kind="success">{status}</Alert>}
            {attrs && (
              <div className="iam-dt-row">
                <Badge tone="info">{Object.keys(attrs).length} attrs</Badge>
              </div>
            )}
          </div>
        </div>
      }
      right={
        !subjectId ? (
          <DetailEmpty message="Enter a subject id to inspect." />
        ) : (
          <div className="iam-dt-detail">
            <div className="iam-dt-detail__head">
              <code>{subjectId}</code>
            </div>
            <Section title="Snapshot">
              {attrs ? (
                <JsonTree data={attrs} defaultOpen />
              ) : (
                <p className="iam-dt-mute" style={{ fontSize: 11 }}>
                  Load to view.
                </p>
              )}
            </Section>
            <Section defaultOpen={false} title="Edit attributes (JSON)">
              <div className="iam-dt-col">
                <TextArea onChange={(e) => setAttrsDraft(e.target.value)} rows={10} value={attrsDraft} />
                <Button disabled={busy || !subjectId} onClick={saveAttrs} variant="primary">
                  save
                </Button>
              </div>
            </Section>
            <Section defaultOpen={false} title="Role assignment">
              <div className="iam-dt-col">
                <div className="iam-dt-grid-2">
                  <Field label="role id">
                    <Input onChange={(e) => setRoleId(e.target.value)} placeholder="editor" value={roleId} />
                  </Field>
                  <Field label="scope (optional)">
                    <Input onChange={(e) => setScope(e.target.value)} placeholder="org-acme" value={scope} />
                  </Field>
                </div>
                <div className="iam-dt-row">
                  <Button disabled={busy || !subjectId} onClick={assign} variant="primary">
                    assign
                  </Button>
                  <Button disabled={busy || !subjectId} onClick={revoke} variant="danger">
                    revoke
                  </Button>
                </div>
              </div>
            </Section>
          </div>
        )
      }
    />
  )
}
