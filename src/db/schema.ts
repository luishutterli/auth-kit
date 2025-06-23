import fs from "node:fs";
import path from "node:path";
import { getConnection } from "./connection";
import { DatabaseError } from "@luishutterli/auth-kit-types";

const schemaExists = async (): Promise<boolean> => {
	try {
		const connection = await getConnection();
		const [rows] = (await connection.query(
			"SELECT schema_name FROM information_schema.schemata WHERE schema_name = 'AuthKit'",
		)) as [any[], any];

		connection.end();

		return Array.isArray(rows) && rows.length > 0;
	} catch (error) {
		console.error("Failed to check if schema exists:", error);
		throw new DatabaseError(
			"Failed to check if schema exists",
			error instanceof Error ? error : undefined,
		);
	}
};

export const createSchema = async (): Promise<void> => {
	if (await schemaExists()) {
		console.log("Database schema already exists, skipping creation");
		return;
	}
	throw new Error(
		"Schema creation is not implemented yet. Please create the schema manually or implement this function.",
	);
};
