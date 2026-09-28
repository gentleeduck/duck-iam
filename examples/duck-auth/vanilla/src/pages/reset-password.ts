import { WEAK_PASSWORD } from '@examples/duck-auth-ui/api'
import * as ui from '@examples/duck-auth-ui/recipes'
import { api } from '../api'
import { createSubmit, Field } from '../form'
import { h } from '../h'
import { AuthLayout } from '../layout'

export function ResetPassword(): HTMLElement {
  const token = new URLSearchParams(location.search).get('token') ?? ''
  const submit = createSubmit(
    (form) => api.resetPassword(token, String(form.get('password'))),
    'Password changed. Sign in with the new one.',
    WEAK_PASSWORD,
  )

  return AuthLayout({
    title: 'Choose a new password',
    description: 'Every signed-in device is signed out once it changes.',
    children: [
      h(
        'form',
        { className: 'grid gap-4', onsubmit: submit.onsubmit },
        Field('New password', { name: 'password', type: 'password', autocomplete: 'new-password' }),
        submit.alert,
        h('button', { type: 'submit', className: ui.button() }, 'Change password'),
      ),
    ],
    footer: [h('a', { href: '/sign-in', className: 'text-foreground' }, 'Back to sign in')],
  })
}
