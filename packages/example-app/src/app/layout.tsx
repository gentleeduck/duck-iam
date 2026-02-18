import type { AppAction, AppResource } from '@gentleduck/example-shared'
import type { PermissionMap } from 'access-engine'
import { Sidebar } from '@/components/sidebar'
import { AccessProvider } from '@/lib/access-client'
import { apiFetch } from '@/lib/api'
import { getCurrentUserId } from '@/lib/auth'

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  let permissions: PermissionMap<AppAction, AppResource> = {} as PermissionMap<AppAction, AppResource>

  const userId = await getCurrentUserId()
  if (userId) {
    try {
      permissions = await apiFetch('/me/permissions', { userId })
    } catch {
      // Backend unavailable — fall back to empty permissions (deny all)
    }
  }

  return (
    <html lang="en">
      <body>
        <AccessProvider permissions={permissions}>
          <div style={{ display: 'flex' }}>
            {userId && <Sidebar />}
            <main style={{ flex: 1 }}>{children}</main>
          </div>
        </AccessProvider>
      </body>
    </html>
  )
}
