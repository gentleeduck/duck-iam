import { Button } from '@gentleduck/registry-ui/button'
import { api } from '../api'
import { Field, Notice, useSubmit } from '../form'
import { AuthLayout } from '../layout'

export function ForgotPassword() {
  const submit = useSubmit((form) => api.forgotPassword(String(form.get('email'))))

  return (
    <AuthLayout
      title="Reset your password"
      description="We will send a reset link to your email."
      footer={
        <a href="/sign-in" className="text-foreground">
          Back to sign in
        </a>
      }>
      <form onSubmit={submit.onSubmit} className="grid gap-4">
        <Field label="Email" name="email" type="email" autoComplete="email" />
        <Notice res={submit.res} done="If that email has an account, its reset link is in the backend's terminal." />
        <Button type="submit" loading={submit.pending}>
          Send reset link
        </Button>
      </form>
    </AuthLayout>
  )
}
