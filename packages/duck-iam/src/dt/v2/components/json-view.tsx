'use client'

import { cn } from '@gentleduck/libs/cn'
import { ChevronDown, ChevronRight } from 'lucide-react'
import React from 'react'

// Collapsible JSON reader for v2; not shared with v1's `components/json-tree`, which needs the injected stylesheet.
// NOTE: must never throw - values are caller-controlled and there is no error boundary here.

/** What kind of thing a value is, for both the colour and the traversal. */
type JsonKind = 'array' | 'boolean' | 'null' | 'number' | 'object' | 'string' | 'other'

function kindOf(value: unknown): JsonKind {
  if (value === null) return 'null'
  if (Array.isArray(value)) return 'array'
  const type = typeof value
  if (type === 'string') return 'string'
  if (type === 'number') return 'number'
  if (type === 'boolean') return 'boolean'
  if (type === 'object') return 'object'
  return 'other'
}

const SCALAR_COLOR: Record<JsonKind, string> = {
  array: 'text-muted-foreground',
  boolean: 'text-sky-700 dark:text-sky-300',
  null: 'text-muted-foreground',
  number: 'text-orange-700 dark:text-orange-300',
  object: 'text-muted-foreground',
  other: 'text-muted-foreground',
  string: 'text-emerald-700 dark:text-emerald-300',
}

/** A scalar as source text. `JSON.stringify` throws on cycles and `BigInt`, so that throw is caught. */
function scalarText(value: unknown): string {
  if (value === undefined) return 'undefined'
  if (value === null) return 'null'
  if (typeof value === 'string') return JSON.stringify(value)
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  try {
    return JSON.stringify(value) ?? String(value)
  } catch {
    return '[unserializable]'
  }
}

/** `{3}` / `[7]` - what a collapsed branch says instead of its contents. */
function preview(value: unknown): string {
  if (Array.isArray(value)) return `[${value.length}]`
  if (typeof value === 'object' && value !== null) return `{${Object.keys(value).length}}`
  return ''
}

function Branch({ depth, label, value }: { depth: number; label?: string; value: unknown }) {
  const kind = kindOf(value)
  const isBranch = kind === 'array' || kind === 'object'
  const [open, setOpen] = React.useState(depth < 1)
  const bodyId = React.useId()

  if (!isBranch) {
    return (
      <div className="flex gap-1.5 py-px ps-[1.125rem]">
        {label !== undefined && <span className="shrink-0 text-muted-foreground">{label}:</span>}
        <span className={cn('min-w-0 break-all', SCALAR_COLOR[kind])}>{scalarText(value)}</span>
      </div>
    )
  }

  // Covers arrays too: their own keys are the indices, used as labels.
  const entries = Object.entries(value as Record<string, unknown>)

  return (
    <div className="py-px">
      <button
        aria-controls={bodyId}
        aria-expanded={open}
        className="flex w-full items-center gap-1 rounded px-0.5 text-start hover:bg-accent focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
        onClick={() => setOpen((o) => !o)}
        type="button">
        <span aria-hidden className="shrink-0 text-muted-foreground/70">
          {open ? <ChevronDown size={11} /> : <ChevronRight size={11} />}
        </span>
        {label !== undefined && <span className="text-muted-foreground">{label}:</span>}
        <span className="text-muted-foreground/70">{preview(value)}</span>
      </button>
      {open && (
        <div className="ms-[0.4375rem] border-border border-s ps-2" id={bodyId}>
          {entries.length === 0 ? (
            <div className="py-px ps-[1.125rem] text-muted-foreground/70">empty</div>
          ) : (
            entries.map(([key, child]) => <Branch depth={depth + 1} key={key} label={key} value={child} />)
          )}
        </div>
      )}
    </div>
  )
}

/**
 * Renders any JSON-ish value as a collapsible tree.
 * @param data - The value to render. Anything, including cyclic objects.
 * @param label - Optional name for the root node.
 */
export function IamV2Json({ data, label }: { data: unknown; label?: string }) {
  return (
    <div className="overflow-x-auto rounded-md border border-border bg-muted/30 p-2 font-mono text-[0.6875rem] leading-relaxed">
      <Branch depth={0} label={label} value={data} />
    </div>
  )
}
