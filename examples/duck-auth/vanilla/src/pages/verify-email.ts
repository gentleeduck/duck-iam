import * as ui from '@examples/duck-auth-ui/recipes'
import { api } from '../api'
import { createSubmit } from '../form'
import { h } from '../h'
import { AuthLayout } from '../layout'

export function VerifyEmail(): HTMLElement {
  const token = new URLSearchParams(location.search).get('token') ?? ''
  const submit = createSubmit(() => api.verifyEmail(token), 'Your email is verified.')

  return AuthLayout({
    title: 'Verify your email',
    description: 'Confirm this address belongs to you.',
    children: [
      h(
        'form',
        { className: 'grid gap-4', onsubmit: submit.onsubmit },
        submit.alert,
        h('button', { type: 'submit', className: ui.button() }, 'Verify email'),
      ),
    ],
    footer: [h('a', { href: '/', className: 'text-foreground' }, 'Go to the dashboard')],
  })
}
