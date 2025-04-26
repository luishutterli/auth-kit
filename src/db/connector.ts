import { Pool } from "pg";
import { DatabaseError, type DatabaseConfig } from "@luishutterli/auth-kit-types";

let pool: Pool | null = null;

export function initDB(config: DatabaseConfig) {
  if (!config || config.type !== "postgres") {
    throw new DatabaseError("Invalid database config");
  }

  if (pool) {
    return pool;
  }

  pool = new Pool({
    host: config.url,
    port: config.port || 5432,
    user: config.username,
    password: config.secret,
    database: config.database || "AuthKit",
  });

  return pool;
}

export function getDB() {
  if (!pool) {
    throw new Error("Database not initialized. Call initDB first.");
  }
  return pool;
}

export async function closeDB() {
  if (pool) {
    await pool.end();
    pool = null;
  }
}
