import * as ui from '@examples/duck-auth-ui/recipes'
import { api } from '../api'
import { createSubmit, Field } from '../form'
import { h } from '../h'
import { AuthLayout } from '../layout'

export function ForgotPassword(): HTMLElement {
  const submit = createSubmit(
    (form) => api.forgotPassword(String(form.get('email'))),
    "If that email has an account, its reset link is in the backend's terminal.",
  )

  return AuthLayout({
    title: 'Reset your password',
    description: 'We will send a reset link to your email.',
    children: [
      h(
        'form',
        { className: 'grid gap-4', onsubmit: submit.onsubmit },
        Field('Email', { name: 'email', type: 'email', autocomplete: 'email' }),
        submit.alert,
        h('button', { type: 'submit', className: ui.button() }, 'Send reset link'),
      ),
    ],
    footer: [h('a', { href: '/sign-in', className: 'text-foreground' }, 'Back to sign in')],
  })
}
