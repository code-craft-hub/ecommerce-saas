import type { Config } from 'drizzle-kit'

export default {
  schema: './src/infrastructure/persistence/schema.ts',
  out: './src/infrastructure/persistence/migrations',
  dialect: 'postgresql',
  dbCredentials: {
    url: process.env.DATABASE_URL!,
  },
  verbose: true,
  strict: true,
} satisfies Config
