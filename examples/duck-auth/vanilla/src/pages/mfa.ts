import * as ui from '@examples/duck-auth-ui/recipes'
import { api } from '../api'
import { createSubmit, Field } from '../form'
import { h } from '../h'
import { AuthLayout } from '../layout'

export function Mfa(): HTMLElement {
  const submit = createSubmit(async (form) => {
    const res = await api.verifyMfa(String(form.get('code')).trim())
    if (!res.ok) return res
    location.assign('/')
    return null
  })

  return AuthLayout({
    title: 'Two-factor check',
    description: 'Enter the code from your authenticator app, or one of your backup codes.',
    children: [
      h(
        'form',
        { className: 'grid gap-4', onsubmit: submit.onsubmit },
        Field('Code', { name: 'code', autocomplete: 'one-time-code' }),
        submit.alert,
        h('button', { type: 'submit', className: ui.button() }, 'Verify'),
      ),
    ],
    footer: [
      h(
        'button',
        {
          type: 'button',
          className: ui.button({ variant: 'link', size: 'sm' }),
          onclick: () => api.signOut().then(() => location.assign('/sign-in')),
        },
        'Use another account',
      ),
    ],
  })
}
