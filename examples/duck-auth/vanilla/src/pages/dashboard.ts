import { type Account, type Envelope, leaveTo, qrCode, type Session, sessionLine } from '@examples/duck-auth-ui/api'
import * as ui from '@examples/duck-auth-ui/recipes'
import { api } from '../api'
import { createSubmit, Field, showNotice } from '../form'
import { h } from '../h'
import { BackendPicker } from '../layout'

export function Dashboard(): HTMLElement {
  document.title = 'Dashboard · duck-auth · Vanilla'
  const page = h('div', { className: 'min-h-svh' })

  api.account().then((res) => {
    if (!res.ok) return location.assign(leaveTo(res.error.code))
    page.append(
      h(
        'header',
        { className: 'flex items-center justify-between border-b px-6 py-3' },
        h('span', { className: 'font-semibold' }, 'duck-auth'),
        h(
          'div',
          { className: 'flex items-center gap-3' },
          BackendPicker(),
          h(
            'button',
            {
              type: 'button',
              className: ui.button({ variant: 'outline', size: 'sm' }),
              onclick: async () => {
                if ((await api.signOut()).ok) location.assign('/sign-in')
              },
            },
            'Sign out',
          ),
        ),
      ),
      h(
        'main',
        { className: 'mx-auto grid max-w-2xl gap-6 p-6' },
        h('h1', { className: 'font-semibold text-2xl' }, `Hello, ${res.data.identity.profile.name}`),
        AccountCard(res.data),
        TwoFactorCard(res.data.totp),
        SessionsCard(res.data.session),
      ),
    )
  })

  return page
}

function Card(title: string, description: Node | string, ...content: Node[]): HTMLDivElement {
  return h(
    'div',
    { className: ui.card.root },
    h(
      'div',
      { className: ui.card.header },
      h('div', { className: ui.card.title }, title),
      h('div', { className: ui.card.description }, description),
    ),
    h('div', { className: `${ui.card.content} grid gap-4` }, ...content),
  )
}

function AccountCard({ identity }: Account): HTMLElement {
  const alert = h('div', { role: 'alert', hidden: true })
  const row = h(
    'div',
    { className: 'flex items-center justify-between gap-4' },
    h(
      'span',
      { className: ui.badge({ variant: identity.emailVerified ? 'secondary' : 'warning' }) },
      identity.emailVerified ? 'Email verified' : 'Email not verified',
    ),
  )
  if (!identity.emailVerified) {
    const resend = h(
      'button',
      { type: 'button', className: ui.button({ variant: 'outline', size: 'sm' }) },
      'Resend the link',
    )
    resend.onclick = async () => {
      resend.disabled = true
      showNotice(alert, await api.resendVerification(), "A new link is in the backend's terminal.")
      resend.disabled = false
    }
    row.append(resend)
  }
  return Card('Account', identity.profile.email, row, alert)
}

function TwoFactorCard(enabled: boolean): HTMLElement {
  const alert = h('div', { role: 'alert', hidden: true })
  const state = h('div', { className: 'grid gap-4' })

  async function run<T>(call: () => Promise<Envelope<T>>, then: (data: T) => void) {
    const buttons = state.querySelectorAll('button')
    for (const button of buttons) button.disabled = true
    const res = await call()
    for (const button of buttons) button.disabled = false
    if (res.ok) then(res.data)
    showNotice(alert, res)
  }

  function showCodes(codes: string[]) {
    state.replaceChildren(
      h('p', { className: 'text-sm' }, 'Save these backup codes. Each one works once.'),
      h('ul', { className: 'grid grid-cols-2 gap-2 font-mono text-sm' }, ...codes.map((code) => h('li', {}, code))),
      h(
        'button',
        { type: 'button', className: `${ui.button()} w-fit`, onclick: () => location.reload() },
        'I saved them',
      ),
    )
  }

  function showSetup(setup: { secret: string; uri: string }) {
    const confirm = createSubmit(async (form) => {
      const res = await api.confirmTotp(String(form.get('code')).trim())
      if (res.ok) showCodes(res.data.backupCodes)
      return res
    })
    state.replaceChildren(
      h(
        'form',
        { className: 'grid gap-4', onsubmit: confirm.onsubmit },
        h(
          'p',
          { className: 'text-sm' },
          'Scan this with an authenticator app, or enter the key below by hand. Then type the code it shows.',
        ),
        h('img', { src: qrCode(setup.uri), alt: 'The key as a QR code', className: 'size-40 rounded-md' }),
        h('code', { className: 'block break-all rounded-md bg-muted p-2 font-mono text-sm' }, setup.secret),
        Field('Code', { name: 'code', autocomplete: 'one-time-code' }),
        confirm.alert,
        h('button', { type: 'submit', className: ui.button() }, 'Turn on'),
      ),
    )
  }

  if (enabled) {
    state.append(
      h(
        'div',
        { className: 'flex flex-wrap items-center gap-2' },
        h('span', { className: ui.badge({ variant: 'secondary' }) }, 'On'),
        h(
          'button',
          {
            type: 'button',
            className: ui.button({ variant: 'outline', size: 'sm' }),
            onclick: () => run(api.newBackupCodes, (data) => showCodes(data.backupCodes)),
          },
          'New backup codes',
        ),
        h(
          'button',
          {
            type: 'button',
            className: ui.button({ variant: 'destructive', size: 'sm' }),
            onclick: () => run(api.removeTotp, () => location.reload()),
          },
          'Turn off',
        ),
      ),
    )
  } else {
    state.append(
      h(
        'button',
        { type: 'button', className: `${ui.button()} w-fit`, onclick: () => run(api.beginTotp, showSetup) },
        'Set up',
      ),
    )
  }

  return Card('Two-factor authentication', 'A code from an authenticator app on every sign-in.', state, alert)
}

function SessionsCard(session: Account['session']): HTMLElement {
  const alert = h('div', { role: 'alert', hidden: true })
  const list = h('ul', { className: 'grid gap-2 text-sm' })
  const button = h(
    'button',
    { type: 'button', className: `${ui.button({ variant: 'outline' })} w-fit`, disabled: true },
    'Sign out other devices',
  )
  let sessions: Session[] = []
  const show = (next: Session[]) => {
    sessions = next
    list.replaceChildren(
      ...next.map((s) =>
        h(
          'li',
          { className: 'flex items-center justify-between gap-4' },
          sessionLine(s),
          ...(s.id === session.id ? [h('span', { className: ui.badge({ variant: 'secondary' }) }, 'This device')] : []),
        ),
      ),
    )
    button.disabled = next.length < 2
  }

  api.sessions().then((res) => {
    if (res.ok) show(res.data.sessions)
  })
  button.onclick = async () => {
    button.disabled = true
    const res = await api.signOutOthers()
    show(res.ok ? sessions.filter((s) => s.id === session.id) : sessions)
    showNotice(alert, res, res.ok ? `Signed out ${res.data.revoked}.` : undefined)
  }

  const ends = new Date(session.expiresAt).toLocaleString()
  return Card('Sessions', `This one is at level ${session.aal} and ends ${ends}.`, list, button, alert)
}
