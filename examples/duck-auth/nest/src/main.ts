import 'reflect-metadata'
import { NestFactory } from '@nestjs/core'
import type { NestExpressApplication } from '@nestjs/platform-express'
import { AppModule } from './app.module'

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule)
  app.disable('x-powered-by')
  const port = Number(process.env.PORT ?? 4600)
  await app.listen(port)
  console.log(`duck-auth nest example on http://localhost:${port}`)
}

bootstrap()
