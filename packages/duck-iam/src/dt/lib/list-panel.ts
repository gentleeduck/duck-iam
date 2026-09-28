import React from 'react'
import { toErrorMessage } from '../../core/errors/normalize'

/** The `id`/`name` shape every list-panel entity has; the filter and selection lookup key on it. */
interface IamListPanelEntity {
  id: string
  name: string
}

/**
 * Shared state behind a devtools "read-only list + string filter + selected detail" panel
 * (policies, roles, in both v1 and v2): fetches once on mount, exposes a refetchable `reload`,
 * and derives the filtered list and current selection from `id`/`name`.
 */
export function useIamListPanel<T extends IamListPanelEntity>(fetchList: () => Promise<T[]>) {
  const [items, setItems] = React.useState<T[]>([])
  const [selected, setSelected] = React.useState<string | null>(null)
  const [error, setError] = React.useState<string | null>(null)
  const [filter, setFilter] = React.useState('')
  const [loading, setLoading] = React.useState(true)

  // Callers pass an inline arrow, so keying `reload` on it would refetch on every render.
  const fetchRef = React.useRef(fetchList)
  fetchRef.current = fetchList
  const reload = React.useCallback(async () => {
    try {
      setError(null)
      setLoading(true)
      setItems(await fetchRef.current())
    } catch (err) {
      setError(toErrorMessage(err))
    } finally {
      setLoading(false)
    }
  }, [])

  React.useEffect(() => {
    void reload()
  }, [reload])

  const query = filter.trim().toLowerCase()
  const filtered = items.filter(
    (item) => item.id.toLowerCase().includes(query) || (item.name ?? '').toLowerCase().includes(query),
  )
  const current = items.find((item) => item.id === selected) ?? null

  return { current, error, filter, filtered, items, loading, reload, selected, setFilter, setSelected }
}
