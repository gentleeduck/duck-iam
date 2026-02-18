import { NestFactory } from '@nestjs/core'
import { AppModule } from './app.module'

async function bootstrap() {
  const app = await NestFactory.create(AppModule)
  app.enableCors()

  const port = process.env.PORT ?? 3001
  await app.listen(port)

  console.log(`NestJS API running on http://localhost:${port}`)
  console.log(`\nTest with:`)
  console.log(`  curl -H "Authorization: Bearer user-alice" http://localhost:${port}/me/permissions`)
  console.log(`  curl -H "Authorization: Bearer user-dave" http://localhost:${port}/posts`)
}
bootstrap()
