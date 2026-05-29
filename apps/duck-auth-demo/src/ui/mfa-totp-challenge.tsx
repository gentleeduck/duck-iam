/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { Button } from '@gentleduck/registry-ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@gentleduck/registry-ui/card'
import { InputOTP, InputOTPGroup, InputOTPSlot, REGEXP_ONLY_DIGITS } from '@gentleduck/registry-ui/input-otp'
import { useState } from 'react'

/**
 * `<MfaTotpChallenge />` — 6-digit OTP capture screen for the TOTP
 * step of an MFA flow. Hooks-free wrapper that takes a `onSubmit`
 * callback so the caller decides whether to invoke
 * `FlowsFacet.completeStepUp` / `verifyTotp` server-side.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function MfaTotpChallenge(props: MfaTotpChallenge.IProps): React.JSX.Element {
  const {
    description = 'Enter the 6-digit code from your authenticator app.',
    onSubmit,
    title = 'Two-factor sign-in',
  } = props
  const [code, setCode] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  return (
    <Card className="w-full max-w-sm">
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent>
        <form
          className="flex flex-col items-center gap-4"
          onSubmit={async (e) => {
            e.preventDefault()
            setLoading(true)
            setError(null)
            try {
              const result = await onSubmit(code)
              if (!result.ok) setError(result.message ?? 'Code did not match.')
            } catch (err) {
              setError((err as Error)?.message ?? 'Verification failed.')
            } finally {
              setLoading(false)
            }
          }}>
          <InputOTP maxLength={6} onValueChange={setCode} pattern={REGEXP_ONLY_DIGITS} value={code}>
            <InputOTPGroup>
              {[0, 1, 2, 3, 4, 5].map((i) => (
                <InputOTPSlot key={i} />
              ))}
            </InputOTPGroup>
          </InputOTP>
          {error ? <p className="text-destructive text-sm">{error}</p> : null}
          <Button className="w-full" disabled={code.length < 6 || loading} type="submit">
            {loading ? 'Verifying…' : 'Verify'}
          </Button>
        </form>
      </CardContent>
    </Card>
  )
}

/**
 * Namespace merge for MfaTotpChallenge.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace MfaTotpChallenge {
  export interface IProps {
    title?: string
    description?: string
    /** Returns `{ ok: false, message }` to surface inline; throwing also displays the error. */
    onSubmit(code: string): Promise<{ ok: true } | { ok: false; message?: string }>
  }
}
