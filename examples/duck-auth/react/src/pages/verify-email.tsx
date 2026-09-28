import { Button } from '@gentleduck/registry-ui/button'
import { api } from '../api'
import { Notice, useSubmit } from '../form'
import { AuthLayout } from '../layout'

export function VerifyEmail() {
  const token = new URLSearchParams(location.search).get('token') ?? ''
  const submit = useSubmit(() => api.verifyEmail(token))

  return (
    <AuthLayout
      title="Verify your email"
      description="Confirm this address belongs to you."
      footer={
        <a href="/" className="text-foreground">
          Go to the dashboard
        </a>
      }>
      <form onSubmit={submit.onSubmit} className="grid gap-4">
        <Notice res={submit.res} done="Your email is verified." />
        <Button type="submit" loading={submit.pending}>
          Verify email
        </Button>
      </form>
    </AuthLayout>
  )
}
