import 'reflect-metadata'
import { NestFactory } from '@nestjs/core'
import { AppModule } from './app.module'

async function bootstrap() {
  const app = await NestFactory.create(AppModule)
  const port = Number(process.env.PORT ?? 3300)
  await app.listen(port)
  console.log(`duck-iam nest example on http://localhost:${port}`)
}

bootstrap()
