import type { AppAuth } from './auth'

export const DEMO = { email: 'ada@duck.test', password: 'duck-auth-examples' }

/** One verified account with a password, so every client can sign in before anyone signs up. */
export async function seedDb(auth: AppAuth) {
  const existing = await auth.identities.getByEmail(DEMO.email).orNull()
  const identity =
    existing ??
    (await auth.identities.create({
      emailVerified: true,
      profile: { email: DEMO.email, name: 'Ada Lovelace', username: 'ada' },
    }))
  await auth.passwords.set(identity.id, DEMO.password, auth.cfg.stores.credentials)
  console.log(`Seeded ${DEMO.email} / ${DEMO.password}`)
}
