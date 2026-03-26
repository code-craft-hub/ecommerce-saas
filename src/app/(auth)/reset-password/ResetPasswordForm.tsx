'use client'

import { useActionState } from 'react'
import { resetPasswordAction } from '@/app/actions/auth'
import type { ActionState } from '@/app/actions/auth'

const initialState: ActionState = {}

export function ResetPasswordForm({ token }: { token: string }) {
  const [state, action, pending] = useActionState(resetPasswordAction, initialState)

  return (
    <form action={action} className="flex flex-col gap-4">
      {/* Hidden token field — server action reads this */}
      <input type="hidden" name="token" value={token} />

      {state.error && (
        <p className="rounded-lg bg-red-50 dark:bg-red-950 border border-red-200 dark:border-red-800 px-4 py-3 text-sm text-red-700 dark:text-red-400">
          {state.error}
        </p>
      )}

      <div className="flex flex-col gap-1">
        <label htmlFor="password" className="text-sm font-medium text-zinc-700 dark:text-zinc-300">
          New password
        </label>
        <input
          id="password"
          name="password"
          type="password"
          autoComplete="new-password"
          required
          placeholder="12+ characters"
          className={`rounded-lg border px-3 py-2 text-sm text-zinc-900 dark:text-zinc-50 placeholder-zinc-400 bg-white dark:bg-zinc-800 focus:outline-none focus:ring-2 focus:ring-zinc-900 dark:focus:ring-zinc-50 ${
            state.fieldErrors?.password ? 'border-red-400 dark:border-red-600' : 'border-zinc-300 dark:border-zinc-700'
          }`}
        />
        {state.fieldErrors?.password && (
          <p className="text-xs text-red-600 dark:text-red-400">{state.fieldErrors.password}</p>
        )}
      </div>

      <div className="flex flex-col gap-1">
        <label htmlFor="confirm" className="text-sm font-medium text-zinc-700 dark:text-zinc-300">
          Confirm password
        </label>
        <input
          id="confirm"
          name="confirm"
          type="password"
          autoComplete="new-password"
          required
          placeholder="Repeat password"
          className={`rounded-lg border px-3 py-2 text-sm text-zinc-900 dark:text-zinc-50 placeholder-zinc-400 bg-white dark:bg-zinc-800 focus:outline-none focus:ring-2 focus:ring-zinc-900 dark:focus:ring-zinc-50 ${
            state.fieldErrors?.confirm ? 'border-red-400 dark:border-red-600' : 'border-zinc-300 dark:border-zinc-700'
          }`}
        />
        {state.fieldErrors?.confirm && (
          <p className="text-xs text-red-600 dark:text-red-400">{state.fieldErrors.confirm}</p>
        )}
      </div>

      <button
        type="submit"
        disabled={pending}
        className="mt-2 rounded-lg bg-zinc-900 dark:bg-zinc-50 px-4 py-2.5 text-sm font-semibold text-white dark:text-zinc-900 hover:bg-zinc-700 dark:hover:bg-zinc-200 disabled:opacity-50 transition-colors"
      >
        {pending ? 'Saving…' : 'Set new password'}
      </button>
    </form>
  )
}
