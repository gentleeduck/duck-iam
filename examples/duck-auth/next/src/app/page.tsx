import { signedIn } from '@examples/duck-auth-shared/session'
import { leaveTo } from '@examples/duck-auth-ui/api'
import { AuthError } from '@gentleduck/auth/core'
import { headers } from 'next/headers'
import { redirect } from 'next/navigation'
import { auth } from '@/auth'
import { Dashboard } from './dashboard'

export default async function HomePage() {
  const { identity, session, totp } = await signedIn(auth, await headers()).catch((err: unknown) => {
    if (!(err instanceof AuthError)) throw err
    redirect(leaveTo(err.code))
  })
  const { email, name, username } = identity.profile

  return (
    <Dashboard
      account={{
        identity: {
          id: identity.id,
          emailVerified: identity.emailVerified,
          profile: { email, name: typeof name === 'string' ? name : username },
        },
        totp,
        session: { id: session.id, aal: session.aal, expiresAt: session.expiresAt.toISOString() },
      }}
    />
  )
}
