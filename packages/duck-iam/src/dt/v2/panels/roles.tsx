'use client'

import { cn } from '@gentleduck/libs/cn'
import { CornerUpRight, RefreshCw, Users } from 'lucide-react'
import React from 'react'
import type { AccessControl } from '../../../core/types'
import { isDevtoolsAllowed } from '../../lib/guard'
import type { IamIDevtoolsEngine } from '../../lib/types'
import {
  IamV2Action,
  IamV2Alert,
  IamV2Chip,
  IamV2Disclosure,
  IamV2Empty,
  IamV2ListRow,
  IamV2PaneBody,
  IamV2PaneHeader,
  IamV2Root,
  IamV2Search,
  IamV2Section,
  IamV2SkeletonRows,
  IamV2Split,
} from '../components/chrome'
import { IamV2Json } from '../components/json-view'
import { IAM_V2_ACTION, IAM_V2_MONO, IAM_V2_RESOURCE } from '../lib/tone'

/** One granted permission; expandable only when it has conditions. */
function PermissionRow({ permission }: { permission: AccessControl.IPermission }) {
  const hasDetail = Boolean(permission.conditions)
  return (
    <IamV2Disclosure
      disabled={!hasDetail}
      summary={
        <>
          <code className={cn(IAM_V2_MONO, IAM_V2_ACTION)}>{permission.action}</code>
          <span className="text-muted-foreground text-xs">on</span>
          <code className={cn(IAM_V2_MONO, IAM_V2_RESOURCE)}>{permission.resource}</code>
          {permission.scope && <IamV2Chip tone="info">{permission.scope}</IamV2Chip>}
          {permission.conditions && <IamV2Chip tone="warn">conditions</IamV2Chip>}
        </>
      }>
      {permission.conditions && <IamV2Json data={permission.conditions} label="conditions" />}
    </IamV2Disclosure>
  )
}

/** Read-only browser for roles, their permissions and inheritance. Assignment lives in the Subjects panel. */
export function IamRolesPanelV2({ engine }: { engine: IamIDevtoolsEngine }) {
  const [roles, setRoles] = React.useState<AccessControl.IRole[]>([])
  const [selected, setSelected] = React.useState<string | null>(null)
  const [error, setError] = React.useState<string | null>(null)
  const [filter, setFilter] = React.useState('')
  const [loading, setLoading] = React.useState(true)

  const load = React.useCallback(async () => {
    try {
      setError(null)
      setLoading(true)
      setRoles(await engine.admin.listRoles())
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }, [engine])

  React.useEffect(() => {
    void load()
  }, [load])

  // Below every hook; guards the whole role catalog.
  if (!isDevtoolsAllowed(engine)) return null

  const query = filter.trim().toLowerCase()
  const filtered = roles.filter(
    (role) => role.id.toLowerCase().includes(query) || (role.name ?? '').toLowerCase().includes(query),
  )
  const current = roles.find((role) => role.id === selected) ?? null

  return (
    <IamV2Root className="flex-1">
      <IamV2Split
        detail={
          !current ? (
            <div className="flex min-h-0 flex-1 items-center justify-center p-6">
              <IamV2Empty
                description="Choose a role on the left to read its permissions and inheritance."
                icon={<Users />}
                title="No role selected"
              />
            </div>
          ) : (
            <>
              <div className="flex shrink-0 flex-wrap items-center gap-2 border-border border-b bg-card px-3 py-2">
                <code className={cn(IAM_V2_MONO, 'font-medium text-foreground')}>{current.id}</code>
                {current.name && <span className="text-muted-foreground text-xs">{current.name}</span>}
                {current.scope && <IamV2Chip tone="info">scope: {current.scope}</IamV2Chip>}
                <span className="ms-auto text-[0.6875rem] text-muted-foreground tabular-nums">
                  {current.permissions.length} permissions
                </span>
              </div>
              <IamV2PaneBody>
                {current.description && (
                  <IamV2Section title="Description">
                    <p className="text-muted-foreground text-xs leading-relaxed">{current.description}</p>
                  </IamV2Section>
                )}
                {current.inherits && current.inherits.length > 0 && (
                  <IamV2Section title="Inherits">
                    <div className="flex flex-wrap gap-1.5">
                      {current.inherits.map((id) => (
                        <IamV2Chip key={id} tone="neutral">
                          <CornerUpRight size={10} />
                          {id}
                        </IamV2Chip>
                      ))}
                    </div>
                  </IamV2Section>
                )}
                <IamV2Section title={`Permissions (${current.permissions.length})`}>
                  <div className="flex flex-col gap-1.5">
                    {current.permissions.map((permission) => (
                      <PermissionRow
                        key={`${permission.action}:${permission.resource}:${permission.scope ?? ''}`}
                        permission={permission}
                      />
                    ))}
                  </div>
                </IamV2Section>
                <IamV2Section defaultOpen={false} title="Raw role">
                  <IamV2Json data={current} />
                </IamV2Section>
              </IamV2PaneBody>
            </>
          )
        }
        list={
          <>
            <IamV2PaneHeader
              actions={
                <IamV2Action label="Reload roles" onClick={() => void load()}>
                  <RefreshCw size={12} />
                  refresh
                </IamV2Action>
              }
              count={filtered.length}
              title="Roles"
            />
            <div className="shrink-0 border-border border-b p-3">
              <IamV2Search onChange={setFilter} placeholder="Filter roles" value={filter} />
            </div>
            <IamV2PaneBody className="gap-1">
              {error && <IamV2Alert tone="error">{error}</IamV2Alert>}
              {!error && loading && roles.length === 0 && <IamV2SkeletonRows />}
              {!error && !loading && filtered.length === 0 && (
                <IamV2Empty
                  description={roles.length === 0 ? 'The adapter holds no roles.' : 'Nothing matches the filter.'}
                  icon={<Users />}
                  title={roles.length === 0 ? 'No roles' : 'No matches'}
                />
              )}
              {filtered.map((role) => (
                <IamV2ListRow
                  active={selected === role.id}
                  description={
                    role.inherits?.length
                      ? `${role.permissions.length} perms · inherits ${role.inherits.join(', ')}`
                      : `${role.permissions.length} perms`
                  }
                  key={role.id}
                  onSelect={() => setSelected(role.id)}
                  title={<code className={IAM_V2_MONO}>{role.id}</code>}
                  tone="allow"
                  trailing={<IamV2Chip tone="neutral">{role.permissions.length}</IamV2Chip>}
                />
              ))}
            </IamV2PaneBody>
          </>
        }
      />
    </IamV2Root>
  )
}
