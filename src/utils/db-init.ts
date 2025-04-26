import { getDB, initDB } from "../db/connector";
import { DatabaseError, type DatabaseConfig } from "@luishutterli/auth-kit-types";

export async function initializeDatabase(
  config: DatabaseConfig,
  autoCreateSchema: boolean,
): Promise<void> {
  initDB(config);

  if (autoCreateSchema) {
    const db = getDB();
    let dbExists: boolean;
    try {
      const res = await db.query(
        "select 1 from information_schema.tables where table_name = 'TAccounts'",
      );
      dbExists = (res.rowCount ?? 0) > 0;
    } catch (_) {
      dbExists = false;
    }

    if (!dbExists) {
      throw new DatabaseError(
        "Automatic schema creation is not supported for this database",
      );
    }
  }
}
