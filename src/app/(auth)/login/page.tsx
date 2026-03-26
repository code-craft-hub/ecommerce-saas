import type { Metadata } from 'next'
import Link from 'next/link'
import { LoginForm } from './LoginForm'

export const metadata: Metadata = { title: 'Sign in' }

export default function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ reset?: string }>
}) {
  return (
    <>
      <h1 className="text-xl font-semibold text-zinc-900 dark:text-zinc-50 mb-1">
        Sign in
      </h1>
      <p className="text-sm text-zinc-500 dark:text-zinc-400 mb-6">
        Welcome back. Enter your credentials to continue.
      </p>

      <LoginForm />

      <p className="mt-6 text-center text-sm text-zinc-500 dark:text-zinc-400">
        No account?{' '}
        <Link
          href="/signup"
          className="font-medium text-zinc-900 dark:text-zinc-50 hover:underline"
        >
          Create one
        </Link>
      </p>
    </>
  )
}
