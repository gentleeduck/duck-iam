import { type Account, leaveTo, qrCode, type Session, sessionLine } from '@examples/duck-auth-ui/api'
import * as ui from '@examples/duck-auth-ui/recipes'
import { authUseSignOut } from '@gentleduck/auth/client/solid'
import type { Envelope } from '@gentleduck/auth/client/vanilla'
import { createSignal, For, Match, onMount, Show, Switch } from 'solid-js'
import { api } from '../api'
import { createSubmit, Field, Notice } from '../form'
import { BackendPicker } from '../layout'

export function Dashboard() {
  document.title = 'Dashboard · duck-auth · Solid'
  const signOut = authUseSignOut()
  const [account, setAccount] = createSignal<Account | null>(null)

  onMount(async () => {
    const res = await api.account()
    if (res.ok) return setAccount(res.data)
    location.assign(leaveTo(res.error.code))
  })

  return (
    <Show when={account()}>
      {(account) => (
        <div class="min-h-svh">
          <header class="flex items-center justify-between border-b px-6 py-3">
            <span class="font-semibold">duck-auth</span>
            <div class="flex items-center gap-3">
              <BackendPicker />
              <button
                type="button"
                class={ui.button({ variant: 'outline', size: 'sm' })}
                disabled={signOut.loading()}
                onClick={async () => {
                  if ((await signOut.mutate()).ok) location.assign('/sign-in')
                }}>
                Sign out
              </button>
            </div>
          </header>
          <main class="mx-auto grid max-w-2xl gap-6 p-6">
            <h1 class="font-semibold text-2xl">Hello, {account().identity.profile.name}</h1>
            <AccountCard account={account()} />
            <TwoFactorCard enabled={account().totp} />
            <SessionsCard session={account().session} />
          </main>
        </div>
      )}
    </Show>
  )
}

function AccountCard(props: { account: Account }) {
  const [res, setRes] = createSignal<Envelope<unknown> | null>(null)
  const [pending, setPending] = createSignal(false)
  const verified = () => props.account.identity.emailVerified

  return (
    <div class={ui.card.root}>
      <div class={ui.card.header}>
        <div class={ui.card.title}>Account</div>
        <div class={ui.card.description}>{props.account.identity.profile.email}</div>
      </div>
      <div class={`${ui.card.content} grid gap-4`}>
        <div class="flex items-center justify-between gap-4">
          <span class={ui.badge({ variant: verified() ? 'secondary' : 'warning' })}>
            {verified() ? 'Email verified' : 'Email not verified'}
          </span>
          <Show when={!verified()}>
            <button
              type="button"
              class={ui.button({ variant: 'outline', size: 'sm' })}
              disabled={pending()}
              onClick={async () => {
                setPending(true)
                setRes(await api.resendVerification())
                setPending(false)
              }}>
              Resend the link
            </button>
          </Show>
        </div>
        <Notice res={res()} done="A new link is in the backend's terminal." />
      </div>
    </div>
  )
}

function TwoFactorCard(props: { enabled: boolean }) {
  const [res, setRes] = createSignal<Envelope<unknown> | null>(null)
  const [setup, setSetup] = createSignal<{ secret: string; uri: string } | null>(null)
  const [codes, setCodes] = createSignal<string[]>([])
  const [pending, setPending] = createSignal(false)
  const confirm = createSubmit(async (form) => {
    const res = await api.confirmTotp(String(form.get('code')).trim())
    if (res.ok) setCodes(res.data.backupCodes)
    return res
  })

  async function run<T>(call: () => Promise<Envelope<T>>, then: (data: T) => void) {
    setPending(true)
    const res = await call()
    setPending(false)
    if (res.ok) then(res.data)
    setRes(res)
  }

  return (
    <div class={ui.card.root}>
      <div class={ui.card.header}>
        <div class={ui.card.title}>Two-factor authentication</div>
        <div class={ui.card.description}>A code from an authenticator app on every sign-in.</div>
      </div>
      <div class={`${ui.card.content} grid gap-4`}>
        <Switch
          fallback={
            <button
              type="button"
              class={`${ui.button()} w-fit`}
              disabled={pending()}
              onClick={() => run(api.beginTotp, (data) => setSetup(data))}>
              Set up
            </button>
          }>
          <Match when={codes().length}>
            <p class="text-sm">Save these backup codes. Each one works once.</p>
            <ul class="grid grid-cols-2 gap-2 font-mono text-sm">
              <For each={codes()}>{(code) => <li>{code}</li>}</For>
            </ul>
            <button type="button" class={`${ui.button()} w-fit`} onClick={() => location.reload()}>
              I saved them
            </button>
          </Match>
          <Match when={setup()}>
            {(setup) => (
              <form onSubmit={confirm.onSubmit} class="grid gap-4">
                <p class="text-sm">
                  Scan this with an authenticator app, or enter the key below by hand. Then type the code it shows.
                </p>
                {/* biome-ignore lint/performance/noImgElement: vite app, not next - <img> is correct */}
                <img src={qrCode(setup().uri)} alt="The key as a QR code" class="size-40 rounded-md" />
                <code class="block break-all rounded-md bg-muted p-2 font-mono text-sm">{setup().secret}</code>
                <Field label="Code" name="code" autocomplete="one-time-code" />
                <Notice res={confirm.res()} />
                <button type="submit" class={ui.button()} disabled={confirm.pending()}>
                  Turn on
                </button>
              </form>
            )}
          </Match>
          <Match when={props.enabled}>
            <div class="flex flex-wrap items-center gap-2">
              <span class={ui.badge({ variant: 'secondary' })}>On</span>
              <button
                type="button"
                class={ui.button({ variant: 'outline', size: 'sm' })}
                disabled={pending()}
                onClick={() => run(api.newBackupCodes, (data) => setCodes(data.backupCodes))}>
                New backup codes
              </button>
              <button
                type="button"
                class={ui.button({ variant: 'destructive', size: 'sm' })}
                disabled={pending()}
                onClick={() => run(api.removeTotp, () => location.reload())}>
                Turn off
              </button>
            </div>
          </Match>
        </Switch>
        <Notice res={res()} />
      </div>
    </div>
  )
}

function SessionsCard(props: { session: Account['session'] }) {
  const [sessions, setSessions] = createSignal<Session[]>([])
  const [res, setRes] = createSignal<Envelope<{ revoked: number }> | null>(null)
  const [pending, setPending] = createSignal(false)
  const done = () => {
    const answer = res()
    return answer?.ok ? `Signed out ${answer.data.revoked}.` : undefined
  }

  onMount(async () => {
    const res = await api.sessions()
    if (res.ok) setSessions(res.data.sessions)
  })

  async function signOutOthers() {
    setPending(true)
    const res = await api.signOutOthers()
    setPending(false)
    if (res.ok) setSessions((all) => all.filter((s) => s.id === props.session.id))
    setRes(res)
  }

  return (
    <div class={ui.card.root}>
      <div class={ui.card.header}>
        <div class={ui.card.title}>Sessions</div>
        <div class={ui.card.description}>
          This one is at level {props.session.aal} and ends {new Date(props.session.expiresAt).toLocaleString()}.
        </div>
      </div>
      <div class={`${ui.card.content} grid gap-4`}>
        <ul class="grid gap-2 text-sm">
          <For each={sessions()}>
            {(s) => (
              <li class="flex items-center justify-between gap-4">
                {sessionLine(s)}
                <Show when={s.id === props.session.id}>
                  <span class={ui.badge({ variant: 'secondary' })}>This device</span>
                </Show>
              </li>
            )}
          </For>
        </ul>
        <button
          type="button"
          class={`${ui.button({ variant: 'outline' })} w-fit`}
          disabled={pending() || sessions().length < 2}
          onClick={signOutOthers}>
          Sign out other devices
        </button>
        <Notice res={res()} done={done()} />
      </div>
    </div>
  )
}
