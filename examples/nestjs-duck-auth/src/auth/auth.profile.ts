/**
 * A type alias, not an interface: `ProfileMetadataBase` carries an index signature, and an interface never
 * satisfies one implicitly.
 */
export type UserProfile = {
  username: string
  email: string
  name: string
}
