import { Hono } from "hono";
import { getConfig } from "./config/config";
import { getConnection } from "./db/connection";
import { createSchema } from "./db/schema";

const VERSION = "1.0.0";
const bannerText = `
    ___         __  __    __ __ _ __
   /   | __  __/ /_/ /_  / //_/(_) /_
  / /| |/ / / / __/ __ \\/ ,<  / / __/
 / ___ / /_/ / /_/ / / / /| |/ / /_
/_/  |_\\__,_/\\__/_/ /_/_/ |_/_/\\__/ v${VERSION} by Luis Hutterli (https://luishutterli.ch)

View on GitHub: https://github.com/luishutterli/auth-kit
`;

console.log(bannerText);

const config = getConfig();

getConnection()
	.then((connection) => {
		console.log("Database connection established successfully");
		connection.release();

		if (config.autoCreateSchema) {
			createSchema().catch((err) => {
				console.error("Failed to create database schema:", err);
			});
		}
	})
	.catch((err) => {
		console.error("Database connection failed:", err);
	});

const app = new Hono();
app.basePath(config.baseUrl ?? "/");

// Routes
app.get("/", (c) => {
	return c.text(`Welcome to AuthKit v${VERSION} by Luis Hutterli!`);
});

export default {
	port: config.port ?? 6575,
	fetch: app.fetch,
};
