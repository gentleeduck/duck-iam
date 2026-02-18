/**
 * Vue 3 integration for access-engine.
 *
 * Usage:
 *
 *   // Plugin setup (main.ts):
 *   import { createAccessPlugin } from "access-engine/client/vue";
 *   app.use(createAccessPlugin(permissionMap));
 *
 *   // In components:
 *   import { useAccess } from "access-engine/client/vue";
 *
 *   const { can, cannot } = useAccess();
 *   const canDelete = can("delete", "post");
 *
 *   // Template directive:
 *   <button v-if="can('delete', 'post')">Delete</button>
 */

import type { PermissionMap } from '../../core/types'

export const ACCESS_INJECTION_KEY = Symbol('access-engine')

/**
 * Create the Vue access control system.
 * Pass your Vue's reactive utilities to avoid hard dependency.
 *
 *   import { ref, computed, inject, provide } from "vue";
 *   import { createVueAccess } from "access-engine/client/vue";
 *
 *   export const { useAccess, provideAccess, createAccessPlugin } = createVueAccess({
 *     ref, computed, inject, provide,
 *   });
 */
export function createVueAccess(vue: { ref: any; computed: any; inject: any; provide: any }) {
  const { ref, computed, inject, provide } = vue

  function createAccessState(initialPermissions: PermissionMap) {
    const permissions = ref<PermissionMap>(initialPermissions)

    const can = (action: string, resource: string, resourceId?: string): boolean => {
      const key = resourceId ? `${action}:${resource}:${resourceId}` : `${action}:${resource}`
      return permissions.value[key] ?? false
    }

    const cannot = (action: string, resource: string, resourceId?: string): boolean => {
      return !can(action, resource, resourceId)
    }

    const update = (newPerms: PermissionMap) => {
      permissions.value = newPerms
    }

    return { permissions, can, cannot, update }
  }

  function provideAccess(permissions: PermissionMap) {
    const state = createAccessState(permissions)
    provide(ACCESS_INJECTION_KEY, state)
    return state
  }

  function useAccess() {
    const state = inject(ACCESS_INJECTION_KEY)
    if (!state) {
      throw new Error('access-engine: useAccess() called without provideAccess(). ' + 'Use provideAccess() in a parent component or install the plugin.')
    }
    return state as ReturnType<typeof createAccessState>
  }

  function createAccessPlugin(permissions: PermissionMap) {
    return {
      install(app: any) {
        const state = createAccessState(permissions)
        app.provide(ACCESS_INJECTION_KEY, state)

        // Make can/cannot available globally
        app.config.globalProperties.$can = state.can
        app.config.globalProperties.$cannot = state.cannot
      },
    }
  }

  return {
    createAccessState,
    provideAccess,
    useAccess,
    createAccessPlugin,
    ACCESS_INJECTION_KEY,
  }
}
