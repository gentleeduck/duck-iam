import 'reflect-metadata'
import { NestFactory } from '@nestjs/core'
import type { NestExpressApplication } from '@nestjs/platform-express'
import { AppModule } from './app.module'

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule, { bodyParser: false })
  app.useBodyParser('json')
  // An IdP answering with a form post, such as Apple, arrives as its raw text for the callback route to parse.
  app.useBodyParser('text', { type: 'application/x-www-form-urlencoded' })
  app.disable('x-powered-by')
  const port = Number(process.env.PORT ?? 4600)
  await app.listen(port)
  console.log(`duck-auth nest example on http://localhost:${port}`)
}

bootstrap()
