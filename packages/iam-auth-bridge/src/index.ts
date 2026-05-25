import type { AuthRoot, Identity, Session } from '@gentleduck/auth/core'

/**
 * Projects an authenticated (session, identity) pair into the shape iam's
 * Engine expects as `Subject`. Apps with custom role storage write their
 * own projector and pass it to {@link withSession}.
 *
 * Returns `any` for now — full iam typing lands when both peers' real
 * `Subject` types are wired through generics. v0.2.0 refactor.
 */
export type IamProjection<Profile = unknown> = (
  identity: Identity.IIdentity<Profile>,
  session: Session.ISession,
) => unknown

/**
 * Default projection: identity.id + identity.profile.roles + AAL / factors / freshness
 * in attributes. Apps storing roles outside `profile.roles` write a custom projector.
 */
export const defaultIamProjection: IamProjection = (identity, session) => {
  const profile = identity.profile as { roles?: string[] } | undefined
  return {
    id: identity.id,
    roles: profile?.roles ?? [],
    attributes: {
      ...((identity.profile as object | undefined) ?? {}),
      tenantId: identity.tenantId,
      aal: session.aal,
      factors: session.factors.map((f) => f.method),
      sessionFresh: session.fresh,
      ...(session.actingAs ? { impersonated: true } : {}),
    },
  }
}

/**
 * Middleware factory — resolves session via auth, returns a lazy subject thunk
 * iam can call only when its policies actually need subject attributes.
 *
 * DESIGN §7.2 — caller integrates with framework router, library stays HTTP-free.
 */
export function withSession<Profile = unknown>(
  auth: AuthRoot<Profile>,
  project: IamProjection<Profile> = defaultIamProjection,
) {
  return async (req: { headers: Headers }) => {
    const resolved = await auth.resolveSession(req)
    if (!resolved) {
      return {
        session: null as Session.ISession | null,
        identity: null as Identity.IIdentity<Profile> | null,
        subject: async () => null,
      }
    }
    let cached: unknown = null
    let computed = false
    return {
      session: resolved.session,
      identity: resolved.identity,
      subject: async () => {
        if (!computed && resolved.identity) {
          cached = project(resolved.identity, resolved.session)
          computed = true
        }
        return cached
      },
    }
  }
}

export type { Identity, Session } from '@gentleduck/auth/core'
