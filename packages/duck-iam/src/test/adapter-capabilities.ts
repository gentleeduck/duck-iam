/**
 * Hides optional adapter methods so the engine's fallback paths actually run.
 * NOTE: `delete` on an instance cannot remove a prototype method; an own `undefined` property shadows it instead.
 */

/** Shadow one optional method with `undefined`, in place. Returns the adapter. */
function hideMethod<A extends object>(adapter: A, name: string): A {
  Object.defineProperty(adapter, name, { configurable: true, value: undefined, writable: true })
  return adapter
}

/** An adapter with no in-place scope update, so `moveOne` emulates one. */
export function withoutInPlaceUpdate<A extends object>(adapter: A): A {
  return hideMethod(adapter, 'updateAssignmentScope')
}

/** An adapter with no set-based writes, so the batch admin takes its row loop. */
export function withoutSetBasedWrites<A extends object>(adapter: A): A {
  return hideMethod(hideMethod(adapter, 'assignRoleMany'), 'revokeRoleMany')
}
