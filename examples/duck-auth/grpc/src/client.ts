import { DEMO } from '@examples/duck-auth-shared/seed'
import { credentials, Metadata, makeClientConstructor, type ServiceError } from '@grpc/grpc-js'
import { authService } from './proto'

// Signs the seeded account in, reads it back, and signs out. Set MFA_CODE once TOTP is enrolled.
const Client = makeClientConstructor(authService, 'Auth')
const client = new Client(`localhost:${process.env.PORT ?? 4900}`, credentials.createInsecure())

function rpc(method: string, request: object, token?: string): Promise<unknown> {
  const metadata = new Metadata()
  if (token) metadata.set('authorization', `Bearer ${token}`)
  const { path, requestSerialize, responseDeserialize } = authService[method] ?? {}
  if (!path || !requestSerialize || !responseDeserialize) throw new Error(`no such rpc: ${method}`)
  return new Promise((resolve, reject) => {
    client.makeUnaryRequest(
      path,
      requestSerialize,
      responseDeserialize,
      request,
      metadata,
      (err: ServiceError | null, res?: unknown) => (err ? reject(err) : resolve(res)),
    )
  })
}

/** A string field of a reply, empty when it carries none. */
function field(reply: unknown, name: 'token' | 'challenge'): string {
  const value = typeof reply === 'object' && reply !== null ? Reflect.get(reply, name) : undefined
  return typeof value === 'string' ? value : ''
}

const signedIn = await rpc('SignIn', DEMO)
let token = field(signedIn, 'token')
const challenge = field(signedIn, 'challenge')
if (challenge) {
  if (!process.env.MFA_CODE) throw new Error('the account has TOTP enrolled: set MFA_CODE')
  token = field(await rpc('VerifyMfa', { challenge, code: process.env.MFA_CODE }), 'token')
}
if (!token) throw new Error('the reply carries no token')
console.log(challenge ? 'signed in with the second factor' : 'signed in')

console.log('me:', await rpc('Me', {}, token).catch((err: ServiceError) => `refused, ${err.details}`))
await rpc('SignOut', {}, token)
console.log('signed out; me:', await rpc('Me', {}, token).catch((err: ServiceError) => `refused, ${err.details}`))
client.close()
