import { resolve } from 'node:path'
import type { ServiceDefinition } from '@grpc/grpc-js'
import { loadSync } from '@grpc/proto-loader'

const definition = loadSync(resolve(import.meta.dir, '../proto/auth.proto'), { keepCase: false, defaults: true })
const service = definition['duckauth.Auth']

// A message or enum carries `format`; a service is a bare map of its methods.
if (!service || 'format' in service) throw new Error('proto/auth.proto declares no duckauth.Auth service')

export const authService: ServiceDefinition = service
