import postgres from 'postgres'
import { drizzle } from 'drizzle-orm/postgres-js'
import * as schema from './schema'

/**
 * Database connection singleton.
 * In Next.js, module-level singletons are shared across requests in the same worker.
 * Use connection pooling (max: 10) to prevent exhaustion.
 */

declare global {
  // eslint-disable-next-line no-var
  var __db: ReturnType<typeof drizzle> | undefined
  // eslint-disable-next-line no-var
  var __pg: ReturnType<typeof postgres> | undefined
}

function createDb() {
  const connectionString = process.env.DATABASE_URL
  if (!connectionString) {
    throw new Error('DATABASE_URL environment variable is not set')
  }

  const sql = postgres(connectionString, {
    max: 10,
    idle_timeout: 20,
    connect_timeout: 10,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : false,
  })

  return { sql, db: drizzle(sql, { schema }) }
}

// In development, reuse the connection across HMR reloads
function getDb() {
  if (process.env.NODE_ENV !== 'production') {
    if (!global.__db) {
      const { sql, db } = createDb()
      global.__pg = sql
      global.__db = db
    }
    return global.__db
  }
  return createDb().db
}

export const db = getDb()
export type DB = typeof db
