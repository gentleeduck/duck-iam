import { prisma } from '@gentleduck/example-shared'
import { Injectable } from '@nestjs/common'

@Injectable()
export class PostsService {
  findAll() {
    return prisma.post.findMany({
      where: { published: true },
      include: { author: { select: { id: true, name: true } } },
    })
  }

  findOne(id: string) {
    return prisma.post.findUnique({
      where: { id },
      include: { author: { select: { id: true, name: true } } },
    })
  }

  create(authorId: string, data: { title: string; body: string }) {
    return prisma.post.create({
      data: { title: data.title, body: data.body, authorId },
    })
  }

  update(id: string, data: { title?: string; body?: string }) {
    return prisma.post.update({
      where: { id },
      data: { title: data.title, body: data.body },
    })
  }

  delete(id: string) {
    return prisma.post.delete({ where: { id } })
  }

  publish(id: string) {
    return prisma.post.update({
      where: { id },
      data: { published: true },
    })
  }
}
