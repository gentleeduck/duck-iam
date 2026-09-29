'use client'

export interface Company {
  id: string
  name: string
}

export interface UserRow {
  id: string
  email: string
  name: string
  companyId: string
}

export interface Product {
  id: string
  companyId: string
  ownerId: string
  name: string
  priceCents: number
}

export interface Order {
  id: string
  companyId: string
  ownerId: string
  productId: string
  quantity: number
  status: string
}

// Matches the `duckiam-sid` cookie transport's CSRF companion (see `shared/src/auth.ts`) — not
// `__Host-` prefixed, because the transport runs with `secure: false` for local dev.
const CSRF_COOKIE = 'duck-csrf'
const CSRF_HEADER = 'x-csrf-token'

function csrfHeader(method: string): Record<string, string> {
  if (method.toUpperCase() === 'GET') return {}
  const match = document.cookie.split('; ').find((entry) => entry.startsWith(`${CSRF_COOKIE}=`))
  return match ? { [CSRF_HEADER]: decodeURIComponent(match.slice(CSRF_COOKIE.length + 1)) } : {}
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const method = init?.method ?? 'GET'
  const res = await fetch(`/api${path}`, {
    ...init,
    credentials: 'include',
    headers: { ...init?.headers, 'content-type': 'application/json', ...csrfHeader(method) },
  })
  const body: unknown = await res.json().catch(() => undefined)
  if (!res.ok) {
    const message = body && typeof body === 'object' && 'error' in body ? String(body.error) : res.statusText
    throw new Error(`${res.status} ${message}`)
  }
  return body as T
}

/** POSTs to one of the auth routes; resolves to duck-auth's refusal code, or `null` once it went through. */
async function authPost(path: string, body: unknown = {}): Promise<string | null> {
  const res = await fetch(`/api/auth${path}`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'content-type': 'application/json', ...csrfHeader('POST') },
    body: JSON.stringify(body),
  })
  if (res.ok) return null
  const payload: unknown = await res.json().catch(() => undefined)
  const error = payload && typeof payload === 'object' && 'error' in payload ? payload.error : undefined
  return error && typeof error === 'object' && 'code' in error && typeof error.code === 'string'
    ? error.code
    : `HTTP_${res.status}`
}

export const api = {
  session: () => request<{ session: object | null }>('/auth/session'),
  signIn: (email: string, password: string) =>
    authPost('/signin', { providerId: 'password', input: { email, password } }),
  signUp: (input: { email: string; password: string; name: string; companyName: string }) => authPost('/signup', input),
  signOut: () => authPost('/signout'),
  permissions: () =>
    request<{ subject: string; scope: string | null; permissions: Record<string, boolean> }>('/me/permissions'),
  company: (id: string) => request<Company>(`/companies/${id}`),
  renameCompany: (id: string, name: string) =>
    request<{ ok: true }>(`/companies/${id}`, { method: 'PATCH', body: JSON.stringify({ name }) }),
  users: () => request<UserRow[]>('/users'),
  deleteUser: (id: string) => request<{ ok: true }>(`/users/${id}`, { method: 'DELETE' }),
  assignRole: (id: string, roleId: string) =>
    request<{ ok: true }>(`/users/${id}/role`, { method: 'POST', body: JSON.stringify({ roleId }) }),
  products: () => request<Product[]>('/products'),
  createProduct: (name: string, priceCents: number) =>
    request<Product>('/products', { method: 'POST', body: JSON.stringify({ name, priceCents }) }),
  deleteProduct: (id: string) => request<{ ok: true }>(`/products/${id}`, { method: 'DELETE' }),
  orders: () => request<Order[]>('/orders'),
  createOrder: (productId: string, quantity: number) =>
    request<Order>('/orders', { method: 'POST', body: JSON.stringify({ productId, quantity }) }),
  updateOrderStatus: (id: string, status: string) =>
    request<{ ok: true }>(`/orders/${id}`, { method: 'PATCH', body: JSON.stringify({ status }) }),
}
