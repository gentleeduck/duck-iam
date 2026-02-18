export const API_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:3001'

export async function apiFetch<T = unknown>(path: string, opts?: RequestInit & { userId?: string }): Promise<T> {
  const { userId, ...init } = opts ?? {}
  const headers: Record<string, string> = {}

  if (userId) headers['Authorization'] = `Bearer ${userId}`

  const res = await fetch(`${API_URL}${path}`, {
    ...init,
    headers: { ...headers, ...(init?.headers as Record<string, string>) },
  })

  if (!res.ok) {
    throw new Error(`API ${res.status}: ${res.statusText}`)
  }

  return res.json()
}
