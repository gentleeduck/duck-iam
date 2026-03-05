import { notFound, redirect } from 'next/navigation'
import { PostActions } from '@/components/post-actions'
import { apiFetch } from '@/lib/api'
import { getCurrentUserId } from '@/lib/auth'

interface Post {
  id: string
  title: string
  body: string
  published: boolean
  authorId: string
  author: { id: string; name: string }
}

interface PostAccess {
  canEdit: boolean
  canDelete: boolean
  canPublish: boolean
}

interface Props {
  params: Promise<{ id: string }>
}

export default async function PostPage({ params }: Props) {
  const { id } = await params
  const userId = await getCurrentUserId()
  if (!userId) redirect('/login')

  // Fetch post data and resource-level permissions from the NestJS backend
  let post: Post
  let access: PostAccess
  try {
    ;[post, access] = await Promise.all([
      apiFetch<Post>(`/posts/${id}`, { userId }),
      apiFetch<PostAccess>(`/posts/${id}/access`, { userId }),
    ])
  } catch {
    notFound()
  }

  return (
    <article>
      <h1>{post.title}</h1>
      <p>By {post.author.name}</p>
      {!post.published && <span className="badge">Draft</span>}
      <div>{post.body}</div>

      {/* Pass server-fetched permissions to client component */}
      <PostActions
        postId={post.id}
        userId={userId}
        canEdit={access.canEdit}
        canDelete={access.canDelete}
        canPublish={access.canPublish}
      />
    </article>
  )
}
