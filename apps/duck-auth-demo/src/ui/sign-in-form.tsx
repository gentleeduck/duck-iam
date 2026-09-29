/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { cn } from '@gentleduck/libs/cn'
import { Alert, AlertDescription, AlertTitle } from '@gentleduck/registry-ui/alert'
import { Button } from '@gentleduck/registry-ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@gentleduck/registry-ui/card'
import { Input } from '@gentleduck/registry-ui/input'
import { Label } from '@gentleduck/registry-ui/label'
import { type FormEvent, useState } from 'react'

/**
 * `<SignInForm />` — email + password form. The caller's `onSubmit` talks to its own sign-in route and answers
 * `{ ok: false, message }` to surface inline. Renders a registry-ui Card with Field-pattern Inputs and a
 * primary Button.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function SignInForm(props: SignInForm.IProps): React.JSX.Element {
  const { className, description, onSubmit, title = 'Sign in' } = props
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const submit = async (e: FormEvent): Promise<void> => {
    e.preventDefault()
    setLoading(true)
    setError(null)
    try {
      const result = await onSubmit(email, password)
      if (!result.ok) setError(result.message ?? 'Wrong email or password.')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Sign-in failed.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <Card className={cn('w-full max-w-sm', className)}>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        {description && <CardDescription>{description}</CardDescription>}
      </CardHeader>
      <CardContent>
        <form className="flex flex-col gap-4" onSubmit={submit}>
          <div className="flex flex-col gap-2">
            <Label htmlFor="duck-auth-email">Email</Label>
            <Input
              autoComplete="email"
              disabled={loading}
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
              disabled={loading}
              id="duck-auth-password"
              onChange={(e) => setPassword(e.target.value)}
              required
              type="password"
              value={password}
            />
          </div>
          {error ? (
            <Alert variant="destructive">
              <AlertTitle>Sign-in failed</AlertTitle>
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          ) : null}
          <Button disabled={loading} type="submit">
            {loading ? 'Signing in…' : 'Sign in'}
          </Button>
        </form>
      </CardContent>
    </Card>
  )
}

/**
 * Namespace merge for SignInForm.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace SignInForm {
  export interface IProps {
    className?: string
    title?: string
    description?: string
    /** Returns `{ ok: false, message }` to surface inline; throwing also displays the error. */
    onSubmit(email: string, password: string): Promise<{ ok: true } | { ok: false; message?: string }>
  }
}
