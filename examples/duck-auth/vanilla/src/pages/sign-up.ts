import { WEAK_PASSWORD } from '@examples/duck-auth-ui/api'
import * as ui from '@examples/duck-auth-ui/recipes'
import { client } from '../api'
import { createSubmit, Field } from '../form'
import { h } from '../h'
import { AuthLayout } from '../layout'

export function SignUp(): HTMLElement {
  const submit = createSubmit(
    (form) => client.signUp({ name: form.get('name'), email: form.get('email'), password: form.get('password') }),
    "Account created. The verification link is in the backend's terminal.",
    WEAK_PASSWORD,
  )

  return AuthLayout({
    title: 'Create an account',
    description: 'Eight characters or more for the password.',
    children: [
      h(
        'form',
        { className: 'grid gap-4', onsubmit: submit.onsubmit },
        Field('Name', { name: 'name', autocomplete: 'name' }),
        Field('Email', { name: 'email', type: 'email', autocomplete: 'email' }),
        Field('Password', { name: 'password', type: 'password', autocomplete: 'new-password' }),
        submit.alert,
        h('button', { type: 'submit', className: ui.button() }, 'Sign up'),
      ),
    ],
    footer: ['Have an account?', h('a', { href: '/sign-in', className: 'text-foreground' }, 'Sign in')],
  })
}
