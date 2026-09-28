'use client'

import { useAuthClient, useSignIn } from '@gentleduck/auth/client/react'
import { type FormEvent, useState } from 'react'

const SEEDED_USERS = [
  'viewer@acme.test',
  'staff@acme.test',
  'manager@acme.test',
  'admin@acme.test',
  'viewer@globex.test',
]
const DEMO_PASSWORD = 'duckiam-examples'

// Friendly copy for the errors a reader will actually hit trying this form; anything else falls
// back to the raw code rather than pretending to know what it means.
const ERROR_MESSAGES: Record<string, string> = {
  AUTH_EMAIL_TAKEN: 'An account with that email already exists — try signing in instead.',
  AUTH_INVALID_CREDENTIALS: 'Wrong email or password, or (on sign up) the password is too short or too common.',
  AUTH_INVALID_PARAMETERS: 'Please fill in every field.',
  AUTH_CSRF: 'Your session expired — refresh the page and try again.',
}

function errorText(res: { ok: false; error: { code: string } }): string {
  return ERROR_MESSAGES[res.error.code] ?? res.error.code
}

export function LoginForm() {
  const [mode, setMode] = useState<'signin' | 'signup'>('signin')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [name, setName] = useState('')
  const [companyName, setCompanyName] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState(false)

  const signIn = useSignIn()
  const client = useAuthClient()

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setError(null)
    setPending(true)
    try {
      if (mode === 'signup') {
        const signedUp = await client.signUp({ email, password, name, companyName })
        if (!signedUp.ok) {
          setError(errorText(signedUp))
          return
        }
      }
      const signedIn = await signIn.mutate({ providerId: 'password', input: { email, password } })
      if (!signedIn.ok) setError(errorText(signedIn))
    } finally {
      setPending(false)
    }
  }

  const fillDemo = (seededEmail: string) => {
    setMode('signin')
    setEmail(seededEmail)
    setPassword(DEMO_PASSWORD)
    setError(null)
  }

  return (
    <section>
      <h1>DuckMarket</h1>
      <p className="muted">
        duck-iam authorization wired through Next.js Route Handlers, gated in the browser with{' '}
        <code>@gentleduck/iam/client/react</code>. Sign-in is real: <code>@gentleduck/auth</code> password credentials
        and cookie sessions, no bearer-token stub.
      </p>

      <div className="row">
        <button type="button" onClick={() => setMode('signin')} disabled={mode === 'signin'}>
          Sign in
        </button>
        <button type="button" onClick={() => setMode('signup')} disabled={mode === 'signup'}>
          Sign up
        </button>
      </div>

      <form className="row" onSubmit={submit}>
        <label>
          Email
          <input
            type="email"
            placeholder="you@company.test"
            autoComplete="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
        </label>
        <label>
          Password
          <input
            type="password"
            placeholder="password"
            autoComplete={mode === 'signup' ? 'new-password' : 'current-password'}
            minLength={mode === 'signup' ? 8 : undefined}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </label>
        {mode === 'signup' && (
          <>
            <label>
              Your name
              <input
                placeholder="your name"
                autoComplete="name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
              />
            </label>
            <label>
              Company name
              <input
                placeholder="company name"
                autoComplete="organization"
                value={companyName}
                onChange={(e) => setCompanyName(e.target.value)}
                required
              />
            </label>
          </>
        )}
        <button type="submit" disabled={pending}>
          {pending ? 'Please wait…' : mode === 'signin' ? 'Sign in' : 'Create account'}
        </button>
      </form>

      <p className="muted">Seeded users, password "{DEMO_PASSWORD}":</p>
      <div className="row">
        {SEEDED_USERS.map((seededEmail) => (
          <button key={seededEmail} type="button" onClick={() => fillDemo(seededEmail)}>
            {seededEmail}
          </button>
        ))}
      </div>

      {error && (
        <p role="alert" style={{ color: 'var(--danger)' }}>
          {error}
        </p>
      )}
    </section>
  )
}
