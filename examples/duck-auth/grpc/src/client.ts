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

function tokenIn(reply: unknown): string {
  if (typeof reply !== 'object' || reply === null || !('token' in reply) || typeof reply.token !== 'string') {
    throw new Error('the reply carries no token')
  }
  return reply.token
}

let token = tokenIn(await rpc('SignIn', DEMO))
console.log('signed in')

if (process.env.MFA_CODE) {
  token = tokenIn(await rpc('VerifyMfa', { code: process.env.MFA_CODE }, token))
  console.log('stepped up to AAL 2')
}

console.log('me:', await rpc('Me', {}, token).catch((err: ServiceError) => `refused, ${err.details}`))
await rpc('SignOut', {}, token)
console.log('signed out; me:', await rpc('Me', {}, token).catch((err: ServiceError) => `refused, ${err.details}`))
client.close()
