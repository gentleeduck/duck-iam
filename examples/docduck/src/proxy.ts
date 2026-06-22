import { getSessionCookie } from 'better-auth/cookies'
import { type NextRequest, NextResponse } from 'next/server'

export function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl

  if (pathname.startsWith('/api/auth') || pathname.startsWith('/_next') || pathname.startsWith('/favicon')) {
    return NextResponse.next()
  }

  const sessionCookie = getSessionCookie(request)
  const isAuthPage = pathname.startsWith('/auth/')

  // Only guard non-auth routes. Auth pages let the layout handle already-logged-in
  // redirects via a real DB session check — cookie existence alone isn't enough
  // (stale cookie after seed/logout would cause an infinite loop).
  if (!sessionCookie && !isAuthPage) {
    return NextResponse.redirect(new URL('/auth/login', request.url))
  }

  return NextResponse.next()
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
}
