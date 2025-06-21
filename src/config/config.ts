import fs from "node:fs";
import { AuthKitError, type AuthKitConfig } from "@luishutterli/auth-kit-types";

const loadConfig = (path: string): AuthKitConfig => {
	console.log(`Loading AuthKit configuration from ${fs.realpathSync(path)}`);
	const config = JSON.parse(fs.readFileSync(path, "utf-8"));
	assertConfig(config);
  console.log("Configuration loaded successfully");
	return config;
};

let config: AuthKitConfig | null = null;
export const getConfig = (path: string): AuthKitConfig => {
	if (config) return config;
	config = loadConfig(path);
	return config;
};

function assertConfig(input: unknown): asserts input is AuthKitConfig {
	if (!input || typeof input !== "object" || Array.isArray(input)) {
		throw new AuthKitError("Config must be a non-array object", "CONFIG_ERROR");
	}
	const cfg = input as Partial<AuthKitConfig>;
	if (
		typeof cfg.name !== "string" ||
		typeof cfg.jwtConfig !== "object" ||
		typeof cfg.passwordHashAlgorithm !== "string" ||
		typeof cfg.passwordSaltLength !== "number" ||
		typeof cfg.databaseConfig !== "object" ||
		typeof cfg.autoCreateSchema !== "boolean"
	) {
		throw new AuthKitError(
			"Missing required AuthKitConfig properties",
			"CONFIG_ERROR",
		);
	}

	// jwtConfig
	if (
		typeof cfg.jwtConfig.secret !== "string" ||
		typeof cfg.jwtConfig.expiresIn !== "string" ||
		typeof cfg.jwtConfig.algorithm !== "string" ||
		!["HMAC-SHA-256"].includes(cfg.jwtConfig.algorithm) ||
		(cfg.jwtConfig.jwtStorageLocation &&
			cfg.jwtConfig.jwtStorageLocation !== "cookie") ||
		(cfg.jwtConfig.cookieName &&
			typeof cfg.jwtConfig.cookieName !== "string") ||
		(cfg.jwtConfig.cookieOptions &&
			(typeof cfg.jwtConfig.cookieOptions.httpOnly !== "boolean" ||
				typeof cfg.jwtConfig.cookieOptions.secure !== "boolean" ||
				!["Strict", "Lax", "None"].includes(
					cfg.jwtConfig.cookieOptions.sameSite,
				) ||
				(cfg.jwtConfig.cookieOptions.maxAge &&
					typeof cfg.jwtConfig.cookieOptions.maxAge !== "number")))
	) {
		throw new AuthKitError("Invalid JWT configuration", "CONFIG_ERROR");
	}

	// databaseConfig
	if (
		typeof cfg.databaseConfig.type !== "string" ||
		cfg.databaseConfig.type !== "postgres" ||
		typeof cfg.databaseConfig.url !== "string" ||
		typeof cfg.databaseConfig.username !== "string" ||
		typeof cfg.databaseConfig.secret !== "string"
	) {
		throw new AuthKitError("Invalid database configuration", "CONFIG_ERROR");
	}

	// passwordPolicy (optional)
	if (cfg.passwordPolicy) {
		if (
			typeof cfg.passwordPolicy.minLength !== "number" ||
			(cfg.passwordPolicy.maxLength &&
				typeof cfg.passwordPolicy.maxLength !== "number") ||
			typeof cfg.passwordPolicy.requireUppercase !== "boolean" ||
			typeof cfg.passwordPolicy.requireLowercase !== "boolean" ||
			typeof cfg.passwordPolicy.requireNumbers !== "boolean"
		) {
			throw new AuthKitError(
				"Invalid password policy configuration",
				"CONFIG_ERROR",
			);
		}
	}
}
