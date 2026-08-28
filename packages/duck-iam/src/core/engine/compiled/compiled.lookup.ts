/** biome-ignore-all lint/style/noNonNullAssertion: hot-path index iteration is guarded by `i < arr.length`. */
import { CellKind, type CompiledTable } from './compiled.types'

/**
 * Phase 1 lookup: CONST_ALLOW / ROLE_MASK only. Returns `'fallthrough'` for
 * any cell compileTable() never touched (untouched, or excluded — wildcard/
 * targeted policy) or for DYNAMIC cells before Task 4 extends this. Callers
 * must route `'fallthrough'` to `evaluateFast`, never treat it as deny.
 */
export function lookup(table: CompiledTable, mask: number, action: string, resource: string): boolean | 'fallthrough' {
  const a = table.actionId.get(action)
  const r = table.resourceId.get(resource)
  if (a === undefined || r === undefined) return 'fallthrough'
  const idx = a * table.nResources + r
  if (table.touched[idx] === 0) return 'fallthrough'
  const k = table.kind[idx]
  if (k === CellKind.CONST_ALLOW) return true
  if (k === CellKind.CONST_DENY) return false
  if (k === CellKind.ROLE_MASK) return (mask & table.allow[idx]!) !== 0
  return 'fallthrough' // DYNAMIC: Task 4
}
