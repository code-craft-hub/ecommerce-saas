import type { Metadata } from 'next'

export const metadata: Metadata = { title: 'Dashboard' }

export default function DashboardPage() {
  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold text-zinc-900 dark:text-zinc-50">Dashboard</h1>
        <p className="mt-1 text-sm text-zinc-500 dark:text-zinc-400">
          You're signed in. Build something great.
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-3">
        {[
          { label: 'Sessions', value: '—', hint: 'Active sessions' },
          { label: 'Last login', value: '—', hint: 'Most recent login' },
          { label: 'Role', value: 'user', hint: 'Your current role' },
        ].map((card) => (
          <div
            key={card.label}
            className="rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-5"
          >
            <p className="text-xs font-medium uppercase tracking-wider text-zinc-400">{card.hint}</p>
            <p className="mt-1 text-2xl font-semibold text-zinc-900 dark:text-zinc-50">{card.value}</p>
            <p className="mt-0.5 text-sm text-zinc-500">{card.label}</p>
          </div>
        ))}
      </div>
    </div>
  )
}
