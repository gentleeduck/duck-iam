'use client'

import { API_URL } from '@/lib/api'

interface PostActionsProps {
  postId: string
  userId: string
  canEdit: boolean
  canDelete: boolean
  canPublish: boolean
}

function authHeaders(userId: string): HeadersInit {
  return { Authorization: `Bearer ${userId}` }
}

export function PostActions({ postId, userId, canEdit, canDelete, canPublish }: PostActionsProps) {
  return (
    <div className="mt-4 flex gap-2">
      {canEdit && (
        <button
          onClick={() => (window.location.href = `/posts/${postId}/edit`)}
          className="rounded bg-blue-600 px-4 py-2 text-white">
          Edit
        </button>
      )}

      {canPublish && (
        <button
          onClick={async () => {
            await fetch(`${API_URL}/posts/${postId}/publish`, {
              method: 'POST',
              headers: authHeaders(userId),
            })
            window.location.reload()
          }}
          className="rounded bg-green-600 px-4 py-2 text-white">
          Publish
        </button>
      )}

      {canDelete && (
        <button
          onClick={async () => {
            if (!confirm('Delete this post?')) return
            await fetch(`${API_URL}/posts/${postId}`, {
              method: 'DELETE',
              headers: authHeaders(userId),
            })
            window.location.href = '/posts'
          }}
          className="rounded bg-red-600 px-4 py-2 text-white">
          Delete
        </button>
      )}
    </div>
  )
}
