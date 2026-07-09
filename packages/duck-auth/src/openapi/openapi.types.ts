export namespace OpenApi {
  export type Config = {
    /** Server URL the routes are mounted under. */
    baseUrl: string
    /** Spec title. Default `Auth API`. */
    title?: string
    /** Spec version. Default `0.1.0`. */
    version?: string
    /** Mount prefix; routes are emitted under `${baseUrl}${prefix}/<name>`. Default `/auth`. */
    prefix?: string
    /** Enabled providers; controls which routes appear. Default emits all. */
    providers?: Array<'password' | 'magic-link' | 'oauth' | 'passkey'>
    /** Add `/.well-known/jwks.json` to the spec (JWT transport only). Default false. */
    includeJwks?: boolean
  }

  export type ISpec = {
    openapi: '3.1.0'
    info: { title: string; version: string; description?: string }
    servers: Array<{ url: string }>
    paths: Record<string, Record<string, unknown>>
    components: {
      schemas: Record<string, unknown>
      securitySchemes: Record<string, unknown>
    }
    security: Array<Record<string, never[]>>
  }
}
