import React from 'react'
import type { IamIFlowEntry, IamIFlowRecorder } from './flow'

/**
 * Shared state behind the Flow panel (v1 and v2): subscribes to the recorder, ticks `now` once a second
 * for relative-age display, filters by verdict and free-text query, and copies the selected entry to the
 * clipboard. Never calls anything on `flow` but `list`/`get`/`subscribe`, so opening the panel cannot
 * perturb what it measures.
 */
export function useIamFlowPanel(flow: IamIFlowRecorder) {
  const [entries, setEntries] = React.useState<readonly IamIFlowEntry[]>(() => flow.list())
  const [selected, setSelected] = React.useState<number | null>(null)
  const [filter, setFilter] = React.useState('')
  const [showAllow, setShowAllow] = React.useState(true)
  const [showDeny, setShowDeny] = React.useState(true)
  const [now, setNow] = React.useState(() => Date.now())
  const [copied, setCopied] = React.useState(false)

  React.useEffect(() => flow.subscribe(() => setEntries(flow.list())), [flow])
  React.useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(id)
  }, [])

  const query = filter.trim().toLowerCase()
  const filtered = entries.filter((entry) => {
    if (!showAllow && entry.allowed) return false
    if (!showDeny && !entry.allowed) return false
    if (!query) return true
    return (
      entry.subjectId.toLowerCase().includes(query) ||
      entry.action.toLowerCase().includes(query) ||
      entry.resource.toLowerCase().includes(query) ||
      (entry.resourceId ?? '').toLowerCase().includes(query)
    )
  })

  const counts = React.useMemo(() => {
    let allow = 0
    let deny = 0
    for (const entry of entries) {
      if (entry.allowed) allow++
      else deny++
    }
    return { allow, deny }
  }, [entries])

  const current = selected === null ? null : (flow.get(selected) ?? null)

  const copyEntry = () => {
    if (!current) return
    void navigator.clipboard
      .writeText(JSON.stringify(current, null, 2))
      .then(() => {
        setCopied(true)
        setTimeout(() => setCopied(false), 1500)
      })
      // Clipboard is permission-gated and missing over plain http; swallow rather than leak an unhandled rejection.
      .catch(() => setCopied(false))
  }

  return {
    copied,
    copyEntry,
    counts,
    current,
    entries,
    filter,
    filtered,
    now,
    selected,
    setFilter,
    setSelected,
    setShowAllow,
    setShowDeny,
    showAllow,
    showDeny,
  }
}
