import { redirect } from 'next/navigation'
import { cookies } from 'next/headers'
import { getContainer } from '@/infrastructure/container'
import { logoutAction } from '@/app/actions/auth'

/**
 * Dashboard layout — server-side auth gate.
 *
 * Reads the access_token cookie, verifies it via the token service,
 * and redirects to /login if invalid or absent.
 *
 * Defense-in-depth: verification happens here AND inside each server action/route handler.
 * Middleware bypass (CVE-2025-29927) cannot circumvent this layout-level check.
 */
export default async function DashboardLayout({
  children,
}: {
  children: React.ReactNode
}) {
  const cookieStore = await cookies()
  const accessToken = cookieStore.get('access_token')?.value

  if (!accessToken) {
    redirect('/login')
  }

  let userName = 'User'
  let userEmail = ''

  try {
    const { tokenService, sessionCache, userRepo } = getContainer()
    const claims = await tokenService.verifyAccessToken(accessToken)

    const isDenylisted = await sessionCache.isTokenDenylisted(claims.jti)
    if (isDenylisted) redirect('/login')

    const user = await userRepo.findById(claims.uid)
    if (!user || user.isDeleted || claims.ver < user.tokenVersion) {
      redirect('/login')
    }

    userName = user.name
    userEmail = user.email.value
  } catch {
    redirect('/login')
  }

  return (
    <div className="min-h-screen bg-zinc-50 dark:bg-zinc-950">
      <header className="border-b border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900">
        <div className="mx-auto flex h-14 max-w-6xl items-center justify-between px-4">
          <span className="font-semibold text-zinc-900 dark:text-zinc-50">MyApp</span>
          <div className="flex items-center gap-4">
            <span className="hidden text-sm text-zinc-500 dark:text-zinc-400 sm:block">
              {userEmail}
            </span>
            <form action={logoutAction}>
              <button
                type="submit"
                className="rounded-lg border border-zinc-200 dark:border-zinc-700 px-3 py-1.5 text-sm font-medium text-zinc-700 dark:text-zinc-300 hover:bg-zinc-50 dark:hover:bg-zinc-800 transition-colors"
              >
                Sign out
              </button>
            </form>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-6xl px-4 py-8">
        {children}
      </main>
    </div>
  )
}
