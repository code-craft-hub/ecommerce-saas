import type { Metadata } from 'next'
import Link from 'next/link'
import { ResetPasswordForm } from './ResetPasswordForm'

export const metadata: Metadata = { title: 'Reset password' }

export default async function ResetPasswordPage({
  searchParams,
}: {
  searchParams: Promise<{ token?: string }>
}) {
  const { token } = await searchParams

  if (!token) {
    return (
      <>
        <h1 className="text-xl font-semibold text-zinc-900 dark:text-zinc-50 mb-1">
          Invalid link
        </h1>
        <p className="text-sm text-zinc-500 dark:text-zinc-400 mb-6">
          This reset link is missing a token.{' '}
          <Link href="/forgot-password" className="font-medium text-zinc-900 dark:text-zinc-50 hover:underline">
            Request a new one.
          </Link>
        </p>
      </>
    )
  }

  return (
    <>
      <h1 className="text-xl font-semibold text-zinc-900 dark:text-zinc-50 mb-1">
        Set new password
      </h1>
      <p className="text-sm text-zinc-500 dark:text-zinc-400 mb-6">
        Choose a strong password for your account.
      </p>

      <ResetPasswordForm token={token} />
    </>
  )
}
