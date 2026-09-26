'use client'

import { RefreshCw } from 'lucide-react'
import type React from 'react'
import {
  IamV2Action,
  IamV2Alert,
  IamV2Empty,
  IamV2PaneBody,
  IamV2PaneHeader,
  IamV2Search,
  IamV2SkeletonRows,
} from './chrome'

/**
 * The reload header, search box, and error/loading/empty/row-list body shared by every v2 "browse a filtered
 * list" panel ({@link IamPoliciesPanelV2}, {@link IamRolesPanelV2}). The detail side stays bespoke per panel -
 * header chips and body-section counts differ too much between entities to share, same as v1's own `right={}`.
 */
export function IamV2ListBrowser<T>({
  emptyIcon,
  error,
  filter,
  filtered,
  items,
  loading,
  noun,
  reload,
  reloadLabel,
  renderRow,
  searchPlaceholder,
  setFilter,
  title,
}: {
  emptyIcon: React.ReactNode
  error: string | null
  filter: string
  filtered: readonly T[]
  items: readonly T[]
  loading: boolean
  /** Singular collection noun used in both empty-state messages, e.g. `"policies"`. */
  noun: string
  reload: () => Promise<void>
  reloadLabel: string
  renderRow: (item: T) => React.ReactNode
  searchPlaceholder: string
  setFilter: (value: string) => void
  title: string
}) {
  return (
    <>
      <IamV2PaneHeader
        actions={
          <IamV2Action label={reloadLabel} onClick={() => void reload()}>
            <RefreshCw size={12} />
            refresh
          </IamV2Action>
        }
        count={filtered.length}
        title={title}
      />
      <div className="shrink-0 border-border border-b p-3">
        <IamV2Search onChange={setFilter} placeholder={searchPlaceholder} value={filter} />
      </div>
      <IamV2PaneBody className="gap-1">
        {error && <IamV2Alert tone="error">{error}</IamV2Alert>}
        {!error && loading && items.length === 0 && <IamV2SkeletonRows />}
        {!error && !loading && filtered.length === 0 && (
          <IamV2Empty
            description={items.length === 0 ? `The adapter holds no ${noun}.` : 'Nothing matches the filter.'}
            icon={emptyIcon}
            title={items.length === 0 ? `No ${noun}` : 'No matches'}
          />
        )}
        {filtered.map(renderRow)}
      </IamV2PaneBody>
    </>
  )
}
