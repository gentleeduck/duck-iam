import { type Account, leaveTo, qrCode, type Session, sessionLine } from '@examples/duck-auth-ui/api'
import { useSignOut } from '@gentleduck/auth/client/react'
import type { Envelope } from '@gentleduck/auth/client/vanilla'
import { Badge } from '@gentleduck/registry-ui/badge'
import { Button } from '@gentleduck/registry-ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@gentleduck/registry-ui/card'
import { useEffect, useState } from 'react'
import { api } from '../api'
import { Field, Notice, useSubmit } from '../form'
import { BackendPicker } from '../layout'

export function Dashboard() {
  const signOut = useSignOut()
  const [account, setAccount] = useState<Account | null>(null)

  useEffect(() => {
    api.account().then((res) => {
      if (res.ok) return setAccount(res.data)
      location.assign(leaveTo(res.error.code))
    })
  }, [])

  if (!account) return null

  return (
    <div className="min-h-svh">
      <title>Dashboard · duck-auth · React</title>
      <header className="flex items-center justify-between border-b px-6 py-3">
        <span className="font-semibold">duck-auth</span>
        <div className="flex items-center gap-3">
          <BackendPicker />
          <Button
            variant="outline"
            size="sm"
            loading={signOut.loading}
            onClick={async () => {
              if ((await signOut.mutate()).ok) location.assign('/sign-in')
            }}>
            Sign out
          </Button>
        </div>
      </header>
      <main className="mx-auto grid max-w-2xl gap-6 p-6">
        <h1 className="font-semibold text-2xl">Hello, {account.identity.profile.name}</h1>
        <AccountCard account={account} />
        <TwoFactorCard enabled={account.totp} />
        <SessionsCard session={account.session} />
      </main>
    </div>
  )
}

function AccountCard({ account }: { account: Account }) {
  const [res, setRes] = useState<Envelope<unknown> | null>(null)
  const [pending, setPending] = useState(false)
  const { profile, emailVerified } = account.identity

  return (
    <Card>
      <CardHeader>
        <CardTitle>Account</CardTitle>
        <CardDescription>{profile.email}</CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        <div className="flex items-center justify-between gap-4">
          <Badge variant={emailVerified ? 'secondary' : 'warning'}>
            {emailVerified ? 'Email verified' : 'Email not verified'}
          </Badge>
          {!emailVerified && (
            <Button
              size="sm"
              variant="outline"
              loading={pending}
              onClick={async () => {
                setPending(true)
                setRes(await api.resendVerification())
                setPending(false)
              }}>
              Resend the link
            </Button>
          )}
        </div>
        <Notice res={res} done="A new link is in the backend's terminal." />
      </CardContent>
    </Card>
  )
}

function TwoFactorCard({ enabled }: { enabled: boolean }) {
  const [res, setRes] = useState<Envelope<unknown> | null>(null)
  const [setup, setSetup] = useState<{ secret: string; uri: string } | null>(null)
  const [codes, setCodes] = useState<string[]>([])
  const [pending, setPending] = useState(false)
  const confirm = useSubmit(async (form) => {
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
    <Card>
      <CardHeader>
        <CardTitle>Two-factor authentication</CardTitle>
        <CardDescription>A code from an authenticator app on every sign-in.</CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        {codes.length > 0 ? (
          <>
            <p className="text-sm">Save these backup codes. Each one works once.</p>
            <ul className="grid grid-cols-2 gap-2 font-mono text-sm">
              {codes.map((code) => (
                <li key={code}>{code}</li>
              ))}
            </ul>
            <Button className="w-fit" onClick={() => location.reload()}>
              I saved them
            </Button>
          </>
        ) : setup ? (
          <form onSubmit={confirm.onSubmit} className="grid gap-4">
            <p className="text-sm">
              Scan this with an authenticator app, or enter the key below by hand. Then type the code it shows.
            </p>
            {/* biome-ignore lint/performance/noImgElement: vite app, not next - <img> is correct */}
            <img src={qrCode(setup.uri)} alt="The key as a QR code" className="size-40 rounded-md" />
            <code className="block break-all rounded-md bg-muted p-2 font-mono text-sm">{setup.secret}</code>
            <Field label="Code" name="code" autoComplete="one-time-code" />
            <Notice res={confirm.res} />
            <Button type="submit" loading={confirm.pending}>
              Turn on
            </Button>
          </form>
        ) : enabled ? (
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant="secondary">On</Badge>
            <Button
              size="sm"
              variant="outline"
              disabled={pending}
              onClick={() => run(api.newBackupCodes, (data) => setCodes(data.backupCodes))}>
              New backup codes
            </Button>
            <Button
              size="sm"
              variant="destructive"
              disabled={pending}
              onClick={() => run(api.removeTotp, () => location.reload())}>
              Turn off
            </Button>
          </div>
        ) : (
          <Button className="w-fit" loading={pending} onClick={() => run(api.beginTotp, setSetup)}>
            Set up
          </Button>
        )}
        <Notice res={res} />
      </CardContent>
    </Card>
  )
}

function SessionsCard({ session }: { session: Account['session'] }) {
  const [sessions, setSessions] = useState<Session[]>([])
  const [res, setRes] = useState<Envelope<{ revoked: number }> | null>(null)
  const [pending, setPending] = useState(false)

  useEffect(() => {
    api.sessions().then((res) => {
      if (res.ok) setSessions(res.data.sessions)
    })
  }, [])

  async function signOutOthers() {
    setPending(true)
    const res = await api.signOutOthers()
    setPending(false)
    if (res.ok) setSessions((all) => all.filter((s) => s.id === session.id))
    setRes(res)
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Sessions</CardTitle>
        <CardDescription>
          This one is at level {session.aal} and ends {new Date(session.expiresAt).toLocaleString()}.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        <ul className="grid gap-2 text-sm">
          {sessions.map((s) => (
            <li key={s.id} className="flex items-center justify-between gap-4">
              {sessionLine(s)}
              {s.id === session.id && <Badge variant="secondary">This device</Badge>}
            </li>
          ))}
        </ul>
        <Button
          className="w-fit"
          variant="outline"
          disabled={sessions.length < 2}
          loading={pending}
          onClick={signOutOthers}>
          Sign out other devices
        </Button>
        <Notice res={res} done={res?.ok ? `Signed out ${res.data.revoked}.` : undefined} />
      </CardContent>
    </Card>
  )
}
