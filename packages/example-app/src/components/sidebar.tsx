'use client'

import { Can, Cannot, useAccess } from '@/lib/access-client'
import { API_URL } from '@/lib/api'

export function Sidebar() {
  const { can } = useAccess()

  return (
    <nav className="h-screen w-64 bg-gray-900 p-4 text-white">
      <h2 className="mb-4 font-bold text-lg">Dashboard</h2>

      <ul className="space-y-2">
        {/* Everyone sees this */}
        <li>
          <a href="/posts" className="block rounded p-2 hover:bg-gray-700">
            Posts
          </a>
        </li>

        {/* Only users who can create posts */}
        <Can action="create" resource="post">
          <li>
            <a href="/posts/new" className="block rounded p-2 hover:bg-gray-700">
              + New Post
            </a>
          </li>
        </Can>

        {/* Only users who can publish */}
        <Can action="publish" resource="post">
          <li>
            <a href="/posts?tab=drafts" className="block rounded p-2 hover:bg-gray-700">
              Drafts & Review
            </a>
          </li>
        </Can>

        {/* Analytics: pro+ only (enforced by plan-gating policy) */}
        <Can
          action="read"
          resource="analytics"
          fallback={
            <li>
              <span className="block cursor-not-allowed rounded p-2 text-gray-500">Analytics (Pro)</span>
            </li>
          }>
          <li>
            <a href="/analytics" className="block rounded p-2 hover:bg-gray-700">
              Analytics
            </a>
          </li>
        </Can>

        {/* Admin section */}
        <Can action="manage" resource="user">
          <li className="mt-4 border-gray-700 border-t pt-4">
            <span className="text-gray-400 text-xs uppercase">Admin</span>
          </li>
          <li>
            <a href="/admin/users" className="block rounded p-2 hover:bg-gray-700">
              Users
            </a>
          </li>
        </Can>

        <Can action="manage" resource="role">
          <li>
            <a href="/admin/roles" className="block rounded p-2 hover:bg-gray-700">
              Roles & Permissions
            </a>
          </li>
        </Can>

        <Can action="update" resource="org">
          <li>
            <a href="/admin/org" className="block rounded p-2 hover:bg-gray-700">
              Organization
            </a>
          </li>
        </Can>

        <Can action="access" resource="billing">
          <li>
            <a href="/billing" className="block rounded p-2 hover:bg-gray-700">
              Billing
            </a>
          </li>
        </Can>

        {/* Export: enterprise only */}
        <Can action="export" resource="post">
          <li>
            <button
              onClick={() => window.open(`${API_URL}/posts/export`, '_blank')}
              className="block w-full rounded p-2 text-left hover:bg-gray-700">
              Export Data
            </button>
          </li>
        </Can>
      </ul>

      {/* Imperative check (alternative to <Can>) */}
      {can('manage', 'user') && (
        <div className="mt-8 rounded bg-gray-800 p-3 text-sm">
          <p className="text-yellow-400">Admin Mode</p>
          <p className="mt-1 text-gray-400 text-xs">You have elevated privileges</p>
        </div>
      )}

      {/* Show upgrade prompt when missing premium features */}
      <Cannot action="read" resource="analytics">
        <div className="mt-8 rounded bg-gradient-to-r from-purple-900 to-blue-900 p-3 text-sm">
          <p className="font-medium">Upgrade to Pro</p>
          <p className="mt-1 text-gray-300 text-xs">Get analytics, exports, and more.</p>
          <a
            href="/billing/upgrade"
            className="mt-2 block rounded bg-white py-1 text-center font-medium text-gray-900 text-xs">
            Upgrade
          </a>
        </div>
      </Cannot>
    </nav>
  )
}
