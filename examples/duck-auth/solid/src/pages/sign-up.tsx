import { WEAK_PASSWORD } from '@examples/duck-auth-ui/api'
import * as ui from '@examples/duck-auth-ui/recipes'
import { api } from '../api'
import { createSubmit, Field, Notice } from '../form'
import { AuthLayout } from '../layout'

export function SignUp() {
  const submit = createSubmit((form) =>
    api.signUp({ name: form.get('name'), email: form.get('email'), password: form.get('password') }),
  )

  return (
    <AuthLayout
      title="Create an account"
      description="Eight characters or more for the password."
      footer={
        <>
          Have an account?
          <a href="/sign-in" class="text-foreground">
            Sign in
          </a>
        </>
      }>
      <form onSubmit={submit.onSubmit} class="grid gap-4">
        <Field label="Name" name="name" autocomplete="name" />
        <Field label="Email" name="email" type="email" autocomplete="email" />
        <Field label="Password" name="password" type="password" autocomplete="new-password" />
        <Notice
          res={submit.res()}
          invalid={WEAK_PASSWORD}
          done="Account created. The verification link is in the backend's terminal."
        />
        <button type="submit" class={ui.button()} disabled={submit.pending()}>
          Sign up
        </button>
      </form>
    </AuthLayout>
  )
}
