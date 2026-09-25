/**
 * Vue 3 integration for duck-iam.
 * `createAccessPlugin`/`useAccess` are not module exports; build them once with `createIamVueAccess(vue)`.
 *
 * Usage (after building the surface, see {@link createIamVueAccess}):
 *
 *   app.use(createAccessPlugin(permissionMap)); // main.ts
 *
 *   const { can } = useAccess();
 *   const canManage = can("manage", "user", undefined, "admin");
 *   <button v-if="can('delete', 'post')">Delete</button>
 */

import type { IamClient } from '../../core/types'
import { iamBuildPermissionKey } from '../../shared/keys'
import { iamAllowedActions, iamHasAnyOn, iamPermissionGranted } from '../../shared/permission-map'

/** Re-exported so consumers get key escaping and introspection instead of splitting keys on `':'`. */
export { iamAllowedActions, iamBuildPermissionKey, iamHasAnyOn }

/**
 * Vue injection key for the access control state.
 * WARN: `Symbol.for`, not `Symbol()`: the ESM and CJS builds must share one key or `inject` misses `provide`.
 */
export const IAM_ACCESS_INJECTION_KEY = Symbol.for('@gentleduck/iam:access')

// Vue is a peer dep; consumers inject their own Vue via createIamVueAccess(vue).

/** Minimal Vue ref type. */
interface VueRef<T> {
  value: T
}

/** Minimal Vue virtual node type. */
interface VNode {
  [key: string]: unknown
}

/** Minimal Vue API surface for dependency injection. */
interface VueLike {
  ref<T>(value: T): VueRef<T>
  computed<T>(getter: () => T): Readonly<VueRef<T>>
  inject<T>(key: symbol | string): T | undefined
  provide(key: symbol | string, value: unknown): void
  defineComponent(options: Record<string, unknown>): unknown
  h(type: unknown, props?: Record<string, unknown> | null, children?: unknown): VNode
}

/** Minimal Vue application instance type. */
interface VueApp {
  provide(key: symbol | string, value: unknown): void
  config: { globalProperties: Record<string, unknown> }
}

/**
 * Builds the Vue 3 access control surface (composables, plugin, components).
 * Takes Vue's reactive utilities to avoid a hard dependency on the framework.
 *
 * @template TAction - Constrains valid action strings.
 * @template TResource - Constrains valid resource strings.
 * @template TScope - Constrains valid scope strings.
 * @param vue - Provides the host Vue module so we never bundle our own copy.
 * @returns `{ createAccessState, provideAccess, useAccess, usePermissions, createAccessPlugin, Can, Cannot, IAM_ACCESS_INJECTION_KEY }`.
 * @example
 * ```ts
 * import { ref, computed, inject, provide, defineComponent, h } from 'vue'
 * import { createIamVueAccess } from '@gentleduck/iam/client/vue'
 *
 * export const { useAccess, createAccessPlugin } = createIamVueAccess({
 *   ref, computed, inject, provide, defineComponent, h,
 * })
 * ```
 */
export function createIamVueAccess<
  TAction extends string = string,
  TResource extends string = string,
  TScope extends string = string,
>(vue: VueLike) {
  const { ref, inject, provide, defineComponent } = vue

  /**
   * Create reactive access control state with can/cannot helpers.
   * NOTE: the map is copied in and frozen, as React's `AccessProvider` and `IamAccessClient` do. `Readonly`
   * erases at runtime, so a shared reference would let `map[key] = true` grant without going through `update()`.
   */
  function createAccessState(initialPermissions: IamClient.PartialPermissionMap<TAction, TResource, TScope>) {
    const snapshot = (map: IamClient.PartialPermissionMap<TAction, TResource, TScope>) => Object.freeze({ ...map })
    const permissions = ref(snapshot(initialPermissions))

    const can = (action: TAction, resource: TResource, resourceId?: string, scope?: TScope): boolean => {
      const key = iamBuildPermissionKey(action, resource, resourceId, scope)
      return iamPermissionGranted(permissions.value, key)
    }

    const cannot = (action: TAction, resource: TResource, resourceId?: string, scope?: TScope): boolean => {
      return !can(action, resource, resourceId, scope)
    }

    const update = (newPerms: IamClient.PartialPermissionMap<TAction, TResource, TScope>) => {
      permissions.value = snapshot(newPerms)
    }

    return {
      permissions,
      can,
      cannot,
      update,
      allowedActions: (resource: TResource) => iamAllowedActions(permissions.value, resource),
      hasAnyOn: (resource: TResource) => iamHasAnyOn(permissions.value, resource),
    }
  }

  /** Provide access control state to child components via Vue's provide/inject. */
  function provideAccess(permissions: IamClient.PartialPermissionMap<TAction, TResource, TScope>) {
    const state = createAccessState(permissions)
    provide(IAM_ACCESS_INJECTION_KEY, state)
    return state
  }

  /** Composable to access the permission state from a parent provider. */
  function useAccess(): ReturnType<typeof createAccessState> {
    // Typed at the injection site, so only presence needs a runtime check.
    const state = inject<ReturnType<typeof createAccessState>>(IAM_ACCESS_INJECTION_KEY)
    if (!state) {
      throw new Error(
        '[@gentleduck/iam:vue] useAccess() called without provideAccess(). ' +
          'Use provideAccess() in a parent component or install the plugin.',
      )
    }
    return state
  }

  /**
   * Fetches a permission map and exposes it as reactive state; same shape as React's `usePermissions`.
   * NOTE: the map is cleared before each load and stays cleared on failure, so a refetch never shows
   * the previous subject's grants.
   *
   * @param fetchFn - Loads the permission map (typically one `fetch` call).
   * @returns `{ permissions, can, cannot, allowedActions, hasAnyOn, loading, error, refetch }`.
   */
  function usePermissions(fetchFn: () => Promise<IamClient.PartialPermissionMap<TAction, TResource, TScope>>) {
    const empty: IamClient.PartialPermissionMap<TAction, TResource, TScope> = {}
    const permissions = ref(empty)
    const loading = ref(true)
    const error = ref<Error | null>(null)

    // NOTE: a run id, not a `cancelled` flag, so a slow earlier load cannot overwrite a newer one.
    let latestRun = 0

    const refetch = (): Promise<void> => {
      const run = ++latestRun
      permissions.value = empty
      error.value = null
      loading.value = true
      return fetchFn().then(
        (perms) => {
          if (run !== latestRun) return
          // `fetchFn` is a trust boundary: a JSON `null` body would reach `iamPermissionGranted` and throw.
          permissions.value = Object.freeze({ ...perms })
          loading.value = false
        },
        (err: unknown) => {
          if (run !== latestRun) return
          error.value = err instanceof Error ? err : new Error(String(err))
          loading.value = false
        },
      )
    }

    const can = (action: TAction, resource: TResource, resourceId?: string, scope?: TScope): boolean => {
      const key = iamBuildPermissionKey(action, resource, resourceId, scope)
      return iamPermissionGranted(permissions.value, key)
    }

    void refetch()

    return {
      allowedActions: (resource: TResource) => iamAllowedActions(permissions.value, resource),
      can,
      cannot: (action: TAction, resource: TResource, resourceId?: string, scope?: TScope) =>
        !can(action, resource, resourceId, scope),
      error,
      hasAnyOn: (resource: TResource) => iamHasAnyOn(permissions.value, resource),
      loading,
      permissions,
      refetch,
    }
  }

  /** Create a Vue plugin that installs access control globally. */
  function createAccessPlugin(permissions: IamClient.PartialPermissionMap<TAction, TResource, TScope>) {
    return {
      install(app: VueApp) {
        const state = createAccessState(permissions)
        app.provide(IAM_ACCESS_INJECTION_KEY, state)

        app.config.globalProperties.$can = state.can
        app.config.globalProperties.$cannot = state.cannot
      },
    }
  }

  /**
   * Renders the default slot when the permission is granted, otherwise the `fallback` slot.
   *
   *   <Can action="read" resource="analytics">
   *     <template #default>Analytics</template>
   *     <template #fallback>Upgrade to Pro</template>
   *   </Can>
   */
  const Can = defineComponent({
    name: 'Can',
    props: {
      action: { type: String, required: true },
      resource: { type: String, required: true },
      resourceId: { type: String, default: undefined },
      scope: { type: String, default: undefined },
    },
    setup(
      props: { action: string; resource: string; resourceId?: string; scope?: string },
      { slots }: { slots: Record<string, (() => VNode[]) | undefined> },
    ) {
      // biome-ignore lint/correctness/useHookAtTopLevel: this is a declarative component
      const { can } = useAccess()
      return () => {
        if (can(props.action as TAction, props.resource as TResource, props.resourceId, props.scope as TScope)) {
          return slots.default?.()
        }
        return slots.fallback?.()
      }
    },
  })

  /** Renders the default slot only when the permission is denied. */
  const Cannot = defineComponent({
    name: 'Cannot',
    props: {
      action: { type: String, required: true },
      resource: { type: String, required: true },
      resourceId: { type: String, default: undefined },
      scope: { type: String, default: undefined },
    },
    setup(
      props: { action: string; resource: string; resourceId?: string; scope?: string },
      { slots }: { slots: Record<string, (() => VNode[]) | undefined> },
    ) {
      // biome-ignore lint/correctness/useHookAtTopLevel: this is a declarative component
      const { cannot } = useAccess()
      return () => {
        if (cannot(props.action as TAction, props.resource as TResource, props.resourceId, props.scope as TScope)) {
          return slots.default?.()
        }
        return null
      }
    },
  })

  return {
    createAccessState,
    provideAccess,
    useAccess,
    usePermissions,
    createAccessPlugin,
    Can,
    Cannot,
    IAM_ACCESS_INJECTION_KEY,
  }
}
