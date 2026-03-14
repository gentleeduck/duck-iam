'use client'

import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { useState } from 'react'
import { signIn } from '@/lib/auth-client'

export function LoginForm() {
  const router = useRouter()
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault()
    setError('')
    setLoading(true)

    const formData = new FormData(e.currentTarget)
    const email = formData.get('email') as string
    const password = formData.get('password') as string

    const result = await signIn.email({ email, password })

    if (result.error) {
      setError(result.error.message ?? 'Login failed')
      setLoading(false)
    } else {
      router.push('/workspaces')
      router.refresh()
    }
  }

  return (
    <div className="rounded-lg border bg-white p-6 shadow-sm">
      <h2 className="mb-4 font-semibold text-xl">Sign in</h2>
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label htmlFor="email" className="mb-1 block font-medium text-sm">
            Email
          </label>
          <input
            id="email"
            name="email"
            type="email"
            required
            placeholder="alice@example.com"
            className="w-full rounded-md border px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring"
          />
        </div>
        <div>
          <label htmlFor="password" className="mb-1 block font-medium text-sm">
            Password
          </label>
          <input
            id="password"
            name="password"
            type="password"
            required
            placeholder="password123"
            className="w-full rounded-md border px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring"
          />
        </div>
        {error && <p className="text-destructive text-sm">{error}</p>}
        <button
          type="submit"
          disabled={loading}
          className="w-full rounded-md bg-primary px-4 py-2 font-medium text-primary-foreground text-sm hover:opacity-90 disabled:opacity-50">
          {loading ? 'Signing in...' : 'Sign in'}
        </button>
      </form>
      <p className="mt-4 text-center text-muted-foreground text-sm">
        Don&apos;t have an account?{' '}
        <Link href="/auth/register" className="font-medium text-foreground underline">
          Register
        </Link>
      </p>
      <div className="mt-4 rounded-md bg-muted p-3 text-muted-foreground text-xs">
        <p className="font-medium">Demo accounts (password: password123):</p>
        <ul className="mt-1 space-y-0.5">
          <li>alice@example.com — owner@acme, viewer@startup</li>
          <li>bob@example.com — editor@acme, owner@startup</li>
          <li>charlie@example.com — viewer@acme</li>
          <li>diana@example.com — admin@acme</li>
        </ul>
      </div>
    </div>
  )
}
