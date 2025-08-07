import { DatabaseError } from "@luishutterli/auth-kit-types";
import { getConnection } from "./connection";

const schemaExists = async (): Promise<boolean> => {
  const connection = await getConnection();
  try {
    const [rows] = (await connection.query(
      "SELECT schema_name FROM information_schema.schemata WHERE schema_name = 'AuthKit'",
    )) as [any[], any];

    return Array.isArray(rows) && rows.length > 0;
  } catch (error) {
    console.error("Failed to check if schema exists:", error);
    throw new DatabaseError(
      "Failed to check if schema exists",
      error instanceof Error ? error : undefined,
    );
  } finally {
    connection.release();
  }
};

// TODO: Note that this check can only be reached if the database connection is established and therefore the schema exists.
export const createSchema = async (): Promise<void> => {
  if (await schemaExists()) {
    console.log("Database schema already exists, skipping creation");
    return;
  }
  
  throw new DatabaseError(
    "Schema creation is not implemented yet. Please create the schema manually or implement this function.",
    new Error("SCHEMA_CREATION_NOT_IMPLEMENTED"),
  );
};
