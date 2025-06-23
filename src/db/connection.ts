import mysql from "mysql2/promise";
import { DatabaseError } from "@luishutterli/auth-kit-types";
import { getConfig } from "../config/config";

let pool: mysql.Pool | null = null;

export const getConnection = async (): Promise<mysql.Connection> => {
	try {
		if (!pool) {
			const config = getConfig();
			const { databaseConfig } = config;

			pool = mysql.createPool({
				host: databaseConfig.url,
				port: databaseConfig.port ?? 3306,
				user: databaseConfig.username,
				password: databaseConfig.secret,
				database: databaseConfig.database,
				waitForConnections: true,
				connectionLimit: 10,
				queueLimit: 0,
			});
		}

		return await pool.getConnection();
	} catch (error) {
		console.error("Failed to create database connection:", error);
		throw new DatabaseError(
			"Failed to connect to the database",
			error instanceof Error ? error : undefined,
		);
	}
};

export const closeConnection = async (): Promise<void> => {
	if (pool) {
		await pool.end();
		pool = null;
	}
};
