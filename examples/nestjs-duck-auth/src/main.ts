import 'reflect-metadata'
import { NestFactory } from '@nestjs/core'
import { AppModule } from './app.module'

async function bootstrap() {
  const app = await NestFactory.create(AppModule)
  app.enableCors({ origin: true, credentials: true })
  const port = Number(process.env.PORT ?? 3000)
  await app.listen(port)
  console.log(`duck-auth NestJS example on http://localhost:${port}`)
}

bootstrap()
