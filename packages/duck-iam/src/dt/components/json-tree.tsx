import React from 'react'
import { ChevronDown, ChevronRight } from './icons'

/** Props for {@link JsonTree}. `level` is supplied by its own recursion; callers pass `data` and optionally a `label`. */
export interface IJsonTreeProps {
  data: unknown
  label?: string
  defaultOpen?: boolean
  level?: number
}

function typeOf(v: unknown): 'object' | 'array' | 'string' | 'number' | 'boolean' | 'null' | 'undefined' | 'function' {
  if (v === null) return 'null'
  if (Array.isArray(v)) return 'array'
  if (typeof v === 'object') return 'object'
  return typeof v as 'string' | 'number' | 'boolean' | 'undefined' | 'function'
}

function previewLen(v: unknown): string {
  if (Array.isArray(v)) return `${v.length} ${v.length === 1 ? 'item' : 'items'}`
  if (v && typeof v === 'object') {
    const n = Object.keys(v as Record<string, unknown>).length
    return `${n} ${n === 1 ? 'item' : 'items'}`
  }
  return ''
}

function Primitive({ value }: { value: unknown }) {
  const t = typeOf(value)
  if (t === 'string') return <span className="iam-dt-json-string">"{String(value)}"</span>
  if (t === 'number') return <span className="iam-dt-json-number">{String(value)}</span>
  if (t === 'boolean') return <span className="iam-dt-json-bool">{String(value)}</span>
  if (t === 'null') return <span className="iam-dt-json-nullish">null</span>
  if (t === 'undefined') return <span className="iam-dt-json-nullish">undefined</span>
  if (t === 'function') return <span className="iam-dt-json-nullish">ƒ()</span>
  return <span>{String(value)}</span>
}

/**
 * Collapsible viewer for arbitrary JSON-ish values - attributes, environments,
 * policy bodies.
 *
 * Everything is collapsed by default except the root, so a subject with a large
 * attribute bag opens as a summary rather than a wall. Non-JSON values
 * (`undefined`, functions) are rendered rather than dropped, because this is a
 * debugging surface and "the field is a function" is exactly the kind of thing
 * worth seeing.
 */
export function JsonTree({ data, label, defaultOpen = false, level = 0 }: IJsonTreeProps) {
  const t = typeOf(data)
  const isContainer = t === 'object' || t === 'array'
  const [open, setOpen] = React.useState(defaultOpen || level === 0)
  const bodyId = React.useId()

  if (!isContainer) {
    return (
      <div className="iam-dt-json">
        <div className="iam-dt-json__leaf">
          {label != null && <span className="iam-dt-json__key">{label}:</span>}
          <Primitive value={data} />
        </div>
      </div>
    )
  }

  const entries = Array.isArray(data)
    ? (data as unknown[]).map((v, i) => [String(i), v] as const)
    : Object.entries(data as Record<string, unknown>)
  const summary = previewLen(data)

  return (
    <div className="iam-dt-json">
      <button
        aria-controls={bodyId}
        aria-expanded={open}
        className="iam-dt-json__btn"
        onClick={() => setOpen((o) => !o)}
        type="button">
        <span aria-hidden className="iam-dt-json__chev">
          {open ? <ChevronDown size={10} /> : <ChevronRight size={10} />}
        </span>
        {label != null && <span className="iam-dt-json__key">{label}:</span>}
        <span className="iam-dt-json__punct">{t === 'array' ? '[' : '{'}</span>
        {!open && <span className="iam-dt-json__punct">...{t === 'array' ? ']' : '}'}</span>}
        <span className="iam-dt-json__summary">{summary}</span>
      </button>
      {open && (
        <div className="iam-dt-json__children" id={bodyId}>
          {entries.map(([k, v]) => (
            <JsonTree data={v} key={k} label={k} level={level + 1} />
          ))}
          <div className="iam-dt-json__close">{t === 'array' ? ']' : '}'}</div>
        </div>
      )}
    </div>
  )
}
