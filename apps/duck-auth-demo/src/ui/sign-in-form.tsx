/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { useSignIn } from '@gentleduck/auth/client/react'
import type { VanillaClient } from '@gentleduck/auth/client/vanilla'
import { cn } from '@gentleduck/libs/cn'
import { Alert, AlertDescription, AlertTitle } from '@gentleduck/registry-ui/alert'
import { Button } from '@gentleduck/registry-ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@gentleduck/registry-ui/card'
import { Input } from '@gentleduck/registry-ui/input'
import { Label } from '@gentleduck/registry-ui/label'
import { type FormEvent, useState } from 'react'

/**
 * `<SignInForm />` — email + password form wired to `useSignIn`.
 * Renders a registry-ui Card with Field-pattern Inputs and a primary
 * Button. Surfaces inline error state via `<Alert />`. Composable —
 * drop into a route as-is, or pass `onSuccess` to redirect.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function SignInForm<Profile = unknown>(props: SignInForm.IProps<Profile>): React.JSX.Element {
  const { className, onSuccess, providerId = 'password', title = 'Sign in', description } = props
  const signIn = useSignIn<Profile>()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')

  const onSubmit = async (e: FormEvent): Promise<void> => {
    e.preventDefault()
    try {
      const result = await signIn.mutate({ input: { email, password }, providerId })
      if (result.ok) onSuccess?.(result)
    } catch {
      // Surfaced through signIn.error
    }
  }

  return (
    <Card className={cn('w-full max-w-sm', className)}>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        {description && <CardDescription>{description}</CardDescription>}
      </CardHeader>
      <CardContent>
        <form className="flex flex-col gap-4" onSubmit={onSubmit}>
          <div className="flex flex-col gap-2">
            <Label htmlFor="duck-auth-email">Email</Label>
            <Input
              autoComplete="email"
              disabled={signIn.loading}
              id="duck-auth-email"
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com"
              required
              type="email"
              value={email}
            />
          </div>
          <div className="flex flex-col gap-2">
            <Label htmlFor="duck-auth-password">Password</Label>
            <Input
              autoComplete="current-password"
              disabled={signIn.loading}
              id="duck-auth-password"
              onChange={(e) => setPassword(e.target.value)}
              required
              type="password"
              value={password}
            />
          </div>
          {signIn.error ? (
            <Alert variant="destructive">
              <AlertTitle>Sign-in failed</AlertTitle>
              <AlertDescription>{describeError(signIn.error)}</AlertDescription>
            </Alert>
          ) : null}
          <Button disabled={signIn.loading} type="submit">
            {signIn.loading ? 'Signing in…' : 'Sign in'}
          </Button>
        </form>
      </CardContent>
    </Card>
  )
}

function describeError(err: unknown): string {
  if (err && typeof err === 'object' && 'meta' in err) {
    const meta = (err as { meta?: { detail?: string } }).meta
    if (meta?.detail) return meta.detail
  }
  if (err && typeof err === 'object' && 'code' in err) {
    return String((err as { code: string }).code)
  }
  return 'Unknown error'
}

/**
 * Namespace merge for SignInForm.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace SignInForm {
  export interface IProps<Profile = unknown> {
    className?: string
    title?: string
    description?: string
    /** Default `'password'`. Use a different id when wiring this form to a non-password provider. */
    providerId?: string
    onSuccess?(result: VanillaClient.ISignInResult<Profile>): void
  }
}
