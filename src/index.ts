import { Hono } from "hono";
import { cors } from "hono/cors";
import { authApp } from "./auth";
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
        process.exit(1);
      });
    }
  })
  .catch((err) => {
    console.error("Database connection failed:", err);
    process.exit(1);
  });

const app = new Hono();
app.basePath(config.baseUrl ?? "/");

// CORS
app.use("*", cors({ origin: "http://localhost:5173", credentials: true }));

app.use("*", async (c, next) => {
  c.header("Server", `AuthKit/${VERSION}`);
  c.header("X-Powered-By", `AuthKit, the modern authentication framework`);

  await next();
});

// Routes
app.get("/", (c) => {
  return c.text(`Welcome to AuthKit v${VERSION} by Luis Hutterli`);
});

app.get("/status", (c) => {
  return c.json({ status: "ok", version: VERSION, service: config.name });
});

const versionRoute = `/v${VERSION.split(".")[0]}`;
app.route(versionRoute, authApp);

export default {
  port: config.port ?? 6575,
  fetch: app.fetch,
};
