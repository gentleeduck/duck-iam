import { landedWith } from '@examples/duck-auth-ui/api'
import * as ui from '@examples/duck-auth-ui/recipes'
import { api, client } from '../api'
import { createSubmit, Field, showNotice } from '../form'
import { h } from '../h'
import { AuthLayout } from '../layout'

export function SignIn(): HTMLElement {
  const submit = createSubmit(async (form) => {
    const email = form.get('email')
    const intent = form.get('intent')
    if (intent === 'magic-link') return client.beginProvider('magic-link', { email })
    if (typeof intent === 'string') {
      // The page is on its way to the IdP once this succeeds, so only a failure has anything to show.
      const res = await client.beginProvider(intent)
      return res.ok ? null : res
    }
    const res = await client.signIn({ providerId: 'password', input: { email, password: form.get('password') } })
    if (!res.ok) return res
    location.assign('/')
    return null
  }, "Your sign-in link is in the backend's terminal.")
  showNotice(submit.alert, landedWith(new URLSearchParams(location.search).get('error')))

  const form = h(
    'form',
    { className: 'grid gap-4', onsubmit: submit.onsubmit },
    Field('Email', { name: 'email', type: 'email', autocomplete: 'email' }),
    Field('Password', { name: 'password', type: 'password', autocomplete: 'current-password' }),
    h('a', { href: '/forgot-password', className: 'text-muted-foreground text-sm' }, 'Forgot your password?'),
    submit.alert,
    h('button', { type: 'submit', className: ui.button() }, 'Sign in'),
    h(
      'button',
      {
        type: 'submit',
        name: 'intent',
        value: 'magic-link',
        formNoValidate: true,
        className: ui.button({ variant: 'outline' }),
      },
      'Email me a sign-in link',
    ),
  )

  api.providers().then((res) => {
    const providers = res.ok ? res.data.providers.filter((provider) => provider.kind === 'oauth') : []
    if (providers.length) form.append(h('div', { className: ui.separator }))
    form.append(
      ...providers.map((provider) =>
        h(
          'button',
          {
            type: 'submit',
            name: 'intent',
            value: provider.id,
            formNoValidate: true,
            className: ui.button({ variant: 'outline' }),
          },
          `Continue with ${provider.id.replace('oauth:', '')}`,
        ),
      ),
    )
  })

  return AuthLayout({
    title: 'Sign in',
    description: 'Welcome back.',
    children: [form],
    footer: ['No account?', h('a', { href: '/sign-up', className: 'text-foreground' }, 'Sign up')],
  })
}
