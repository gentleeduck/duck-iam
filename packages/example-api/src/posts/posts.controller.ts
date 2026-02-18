import type { AppAction, AppResource, AppRole, AppScope } from '@gentleduck/example-shared'
import {
  Body,
  Controller,
  Delete,
  ForbiddenException,
  Get,
  Inject,
  NotFoundException,
  Param,
  Post,
  Put,
  Req,
} from '@nestjs/common'
import type { Engine } from 'access-engine'
import { ACCESS_ENGINE_TOKEN } from 'access-engine/server/nest'
import { Authorize } from '../access/authorize'
import { type AuthenticatedRequest, extractUserId } from '../shared/auth'
import type { PostsService } from './posts.service'

@Controller('posts')
export class PostsController {
  constructor(
    private readonly posts: PostsService,
    @Inject(ACCESS_ENGINE_TOKEN)
    private readonly engine: Engine<AppAction, AppResource, AppRole, AppScope>,
  ) {}

  @Get()
  findAll() {
    return this.posts.findAll()
  }

  @Post()
  @Authorize({ action: 'create', resource: 'post' })
  async create(@Req() req: AuthenticatedRequest, @Body() body: { title: string; body: string }) {
    const userId = extractUserId(req)
    return this.posts.create(userId, body)
  }

  @Get(':id')
  @Authorize({ action: 'read', resource: 'post' })
  async findOne(@Req() req: AuthenticatedRequest, @Param('id') id: string) {
    const userId = extractUserId(req)
    const post = await this.posts.findOne(id)
    if (!post) throw new NotFoundException()

    // Enforce unpublished-visibility: only owner/editors can see drafts
    if (!post.published) {
      const allowed = await this.engine.can(userId, 'read', {
        type: 'post',
        id: post.id,
        attributes: { ownerId: post.authorId, published: post.published },
      })
      if (!allowed) throw new NotFoundException()
    }

    return post
  }

  @Put(':id')
  @Authorize({ action: 'update', resource: 'post' })
  async update(
    @Req() req: AuthenticatedRequest,
    @Param('id') id: string,
    @Body() body: { title?: string; body?: string },
  ) {
    const userId = extractUserId(req)
    const post = await this.posts.findOne(id)
    if (!post) throw new NotFoundException()

    const allowed = await this.engine.can(userId, 'update', {
      type: 'post',
      id: post.id,
      attributes: { ownerId: post.authorId, published: post.published },
    })
    if (!allowed) throw new ForbiddenException()

    return this.posts.update(id, body)
  }

  @Delete(':id')
  @Authorize({ action: 'delete', resource: 'post' })
  async remove(@Req() req: AuthenticatedRequest, @Param('id') id: string) {
    const userId = extractUserId(req)
    const post = await this.posts.findOne(id)
    if (!post) throw new NotFoundException()

    const allowed = await this.engine.can(userId, 'delete', {
      type: 'post',
      id: post.id,
      attributes: { ownerId: post.authorId },
    })
    if (!allowed) throw new ForbiddenException()

    return this.posts.delete(id)
  }

  @Post(':id/publish')
  @Authorize({ action: 'publish', resource: 'post' })
  async publish(@Req() req: AuthenticatedRequest, @Param('id') id: string) {
    const userId = extractUserId(req)
    const post = await this.posts.findOne(id)
    if (!post) throw new NotFoundException()

    const allowed = await this.engine.can(userId, 'publish', {
      type: 'post',
      id: post.id,
      attributes: { ownerId: post.authorId, published: post.published },
    })
    if (!allowed) throw new ForbiddenException()

    return this.posts.publish(id)
  }

  @Get(':id/access')
  @Authorize({ action: 'read', resource: 'post' })
  async getAccess(@Req() req: AuthenticatedRequest, @Param('id') id: string) {
    const userId = extractUserId(req)
    const post = await this.posts.findOne(id)
    if (!post) throw new NotFoundException()

    const [canEdit, canDelete, canPublish] = await Promise.all([
      this.engine.can(userId, 'update', {
        type: 'post',
        id: post.id,
        attributes: { ownerId: post.authorId, published: post.published },
      }),
      this.engine.can(userId, 'delete', {
        type: 'post',
        id: post.id,
        attributes: { ownerId: post.authorId },
      }),
      this.engine.can(userId, 'publish', {
        type: 'post',
        id: post.id,
        attributes: { ownerId: post.authorId },
      }),
    ])

    return { canEdit, canDelete, canPublish: canPublish && !post.published }
  }
}
