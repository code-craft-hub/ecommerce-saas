import type { Metadata } from 'next'
import Link from 'next/link'
import { getContainer } from '@/infrastructure/container'

export const metadata: Metadata = { title: 'Verify email' }

export default async function VerifyEmailPage({
  searchParams,
}: {
  searchParams: Promise<{ token?: string }>
}) {
  const { token } = await searchParams

  if (!token) {
    return <VerifyResult ok={false} message="Verification link is missing a token." />
  }

  const { verifyEmailUseCase } = getContainer()
  const result = await verifyEmailUseCase.execute({ token })

  if (result.isErr()) {
    const msg =
      result.error.code === 'TOKEN_EXPIRED'
        ? 'This verification link has expired. Please request a new one.'
        : result.error.code === 'INVALID_TOKEN'
          ? 'This verification link is invalid.'
          : 'Verification failed. Please try again.'
    return <VerifyResult ok={false} message={msg} />
  }

  return <VerifyResult ok={true} message="Your email has been verified. You can now sign in." />
}

function VerifyResult({ ok, message }: { ok: boolean; message: string }) {
  return (
    <>
      <div
        className={`mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full ${
          ok ? 'bg-green-100 dark:bg-green-900' : 'bg-red-100 dark:bg-red-900'
        }`}
      >
        {ok ? (
          <svg className="h-6 w-6 text-green-600 dark:text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
          </svg>
        ) : (
          <svg className="h-6 w-6 text-red-600 dark:text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
          </svg>
        )}
      </div>
      <h1 className="text-center text-xl font-semibold text-zinc-900 dark:text-zinc-50 mb-2">
        {ok ? 'Email verified' : 'Verification failed'}
      </h1>
      <p className="text-center text-sm text-zinc-500 dark:text-zinc-400 mb-6">{message}</p>
      <Link
        href={ok ? '/login' : '/forgot-password'}
        className="block text-center rounded-lg bg-zinc-900 dark:bg-zinc-50 px-4 py-2.5 text-sm font-semibold text-white dark:text-zinc-900 hover:bg-zinc-700 dark:hover:bg-zinc-200 transition-colors"
      >
        {ok ? 'Sign in' : 'Request new link'}
      </Link>
    </>
  )
}
