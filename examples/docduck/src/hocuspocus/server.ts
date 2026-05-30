import { Server } from '@hocuspocus/server'
import { onAuthenticate } from './auth-hook'
import { onLoadDocument, onStoreDocument } from './store-hook'

const server = new Server({
  port: 8888,
  onAuthenticate,
  onLoadDocument,
  onStoreDocument,
})

server.listen().then(() => {
  console.log('Hocuspocus server running on ws://localhost:8888')
})
