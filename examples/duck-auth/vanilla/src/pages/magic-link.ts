import * as ui from '@examples/duck-auth-ui/recipes'
import { api } from '../api'
import { createSubmit } from '../form'
import { h } from '../h'
import { AuthLayout } from '../layout'

export function MagicLink(): HTMLElement {
  const token = new URLSearchParams(location.search).get('token') ?? ''
  const submit = createSubmit(async () => {
    const res = await api.signIn('magic-link', { token })
    if (!res.ok) return res
    location.assign('/')
    return null
  })

  return AuthLayout({
    title: 'Sign in with your link',
    description: 'The link works once and expires soon.',
    children: [
      h(
        'form',
        { className: 'grid gap-4', onsubmit: submit.onsubmit },
        submit.alert,
        h('button', { type: 'submit', className: ui.button() }, 'Sign me in'),
      ),
    ],
  })
}
