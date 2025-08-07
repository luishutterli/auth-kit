import fs from "node:fs";
import { type AuthKitConfig, AuthKitError } from "@luishutterli/auth-kit-types";

interface JWTConfigCandidate {
  secret?: unknown;
  expiresIn?: unknown;
  algorithm?: unknown;
  jwtStorageLocation?: unknown;
  issuer?: unknown;
  refreshExpiresIn?: unknown;
  cookieName?: unknown;
  refreshCookieName?: unknown;
  cookieOptions?: unknown;
  refreshCookieOptions?: unknown;
}

interface CookieOptionsCandidate {
  httpOnly?: unknown;
  secure?: unknown;
  sameSite?: unknown;
  maxAge?: unknown;
  path?: unknown;
  domain?: unknown;
}

interface DatabaseConfigCandidate {
  type?: unknown;
  url?: unknown;
  username?: unknown;
  secret?: unknown;
  port?: unknown;
  database?: unknown;
}

interface PasswordPolicyCandidate {
  minLength?: unknown;
  maxLength?: unknown;
  requireUppercase?: unknown;
  requireLowercase?: unknown;
  requireNumbers?: unknown;
  requireSpecialCharacters?: unknown;
}

interface OAuthProviderCandidate {
  name?: unknown;
  clientId?: unknown;
  clientSecret?: unknown;
  authorizationEndpoint?: unknown;
  tokenEndpoint?: unknown;
  redirectUri?: unknown;
  scope?: unknown;
  userInfoEndpoint?: unknown;
}

const substituteEnvironmentVariables = (text: string): string => {
  return text.replace(/\$\{([^}:]+)(?::([^}]*))?\}/g, (_match, envVar, defaultValue) => {
    const value = process.env[envVar];
    if (value !== undefined) return value;
    if (defaultValue !== undefined) return defaultValue;
    throw new AuthKitError(
      `Environment variable ${envVar} is not defined and no default value provided`,
      "CONFIG_ERROR",
    );
  });
};

const loadConfig = (path: string): AuthKitConfig => {
  console.log(`Loading AuthKit configuration from ${fs.realpathSync(path)}`);

  let configText = fs.readFileSync(path, "utf-8");
  configText = substituteEnvironmentVariables(configText);

  const config = JSON.parse(configText) as Record<string, unknown>;

  assertConfig(config);
  console.log("Configuration loaded successfully");
  return config;
};

let config: AuthKitConfig | null = null;
export const getConfig = (): AuthKitConfig => {
  if (config) return config;
  config = loadConfig("./config/config.json");

  // Populate some defaults if not provided
  config.baseUrl ??= "/";
  config.jwtConfig.issuer ??= config.name;
  config.jwtConfig.refreshExpiresIn ??= "7d";
  config.jwtConfig.refreshCookieName ??= "authkit_refresh";
  config.jwtConfig.refreshCookieOptions ??= config.jwtConfig.cookieOptions;
  config.enforceVerifiedEmail ??= true;
  config.emailEnumerationProtection ??= true;

  return config;
};

const validateRequiredProperties = (cfg: Partial<AuthKitConfig>): void => {
  if (typeof cfg.name !== "string")
    throw new AuthKitError("Missing or invalid 'name' property - must be a string", "CONFIG_ERROR");
  
  if (typeof cfg.jwtConfig !== "object" || cfg.jwtConfig === null)
    throw new AuthKitError("Missing or invalid 'jwtConfig' property - must be an object", "CONFIG_ERROR");
  
  if (typeof cfg.passwordHashAlgorithm !== "string")
    throw new AuthKitError("Missing or invalid 'passwordHashAlgorithm' property - must be a string", "CONFIG_ERROR");
  
  if (!["SHA-512"].includes(cfg.passwordHashAlgorithm))
    throw new AuthKitError(`Invalid 'passwordHashAlgorithm' value: '${cfg.passwordHashAlgorithm}' - must be one of: SHA-512`, "CONFIG_ERROR");
  
  if (typeof cfg.passwordSaltLength !== "number")
    throw new AuthKitError("Missing or invalid 'passwordSaltLength' property - must be a number", "CONFIG_ERROR");
  
  if (typeof cfg.databaseConfig !== "object" || cfg.databaseConfig === null)
    throw new AuthKitError("Missing or invalid 'databaseConfig' property - must be an object", "CONFIG_ERROR");
  
  if (typeof cfg.autoCreateSchema !== "boolean")
    throw new AuthKitError("Missing or invalid 'autoCreateSchema' property - must be a boolean", "CONFIG_ERROR");
};

const validateOptionalProperties = (cfg: Partial<AuthKitConfig>): void => {
  if (cfg.baseUrl !== undefined && typeof cfg.baseUrl !== "string")
    throw new AuthKitError("baseUrl must be a string when provided", "CONFIG_ERROR");

  if (cfg.port !== undefined && typeof cfg.port !== "number")
    throw new AuthKitError("Port must be a number", "CONFIG_ERROR");

  if (cfg.enforceVerifiedEmail !== undefined && typeof cfg.enforceVerifiedEmail !== "boolean")
    throw new AuthKitError("enforceVerifiedEmail must be a boolean", "CONFIG_ERROR");

  if (cfg.emailEnumerationProtection !== undefined && typeof cfg.emailEnumerationProtection !== "boolean")
    throw new AuthKitError("emailEnumerationProtection must be a boolean", "CONFIG_ERROR");
};

const validateJWTConfigRequired = (jwt: JWTConfigCandidate): void => {
  if (typeof jwt.secret !== "string")
    throw new AuthKitError("Missing or invalid 'jwtConfig.secret' property - must be a string", "CONFIG_ERROR");
  
  if (typeof jwt.expiresIn !== "string")
    throw new AuthKitError("Missing or invalid 'jwtConfig.expiresIn' property - must be a string", "CONFIG_ERROR");
  
  if (typeof jwt.algorithm !== "string")
    throw new AuthKitError("Missing or invalid 'jwtConfig.algorithm' property - must be a string", "CONFIG_ERROR");
  
  if (!["HS256"].includes(jwt.algorithm))
    throw new AuthKitError(`Invalid 'jwtConfig.algorithm' value: '${jwt.algorithm}' - must be one of: HS256`, "CONFIG_ERROR");
  
  if (typeof jwt.jwtStorageLocation !== "string")
    throw new AuthKitError("Missing or invalid 'jwtConfig.jwtStorageLocation' property - must be a string", "CONFIG_ERROR");
  
  if (jwt.jwtStorageLocation !== "cookie")
    throw new AuthKitError(`Invalid 'jwtConfig.jwtStorageLocation' value: '${jwt.jwtStorageLocation}' - must be 'cookie'`, "CONFIG_ERROR");
};

const validateJWTConfigOptional = (jwt: JWTConfigCandidate): void => {
  if (jwt.issuer !== undefined && typeof jwt.issuer !== "string")
    throw new AuthKitError("Invalid 'jwtConfig.issuer' property - must be a string when provided", "CONFIG_ERROR");
  
  if (jwt.refreshExpiresIn !== undefined && typeof jwt.refreshExpiresIn !== "string")
    throw new AuthKitError("Invalid 'jwtConfig.refreshExpiresIn' property - must be a string when provided", "CONFIG_ERROR");
  
  if (jwt.cookieName !== undefined && typeof jwt.cookieName !== "string")
    throw new AuthKitError("Invalid 'jwtConfig.cookieName' property - must be a string when provided", "CONFIG_ERROR");
  
  if (jwt.refreshCookieName !== undefined && typeof jwt.refreshCookieName !== "string")
    throw new AuthKitError("Invalid 'jwtConfig.refreshCookieName' property - must be a string when provided", "CONFIG_ERROR");
};

const validateJWTConfig = (jwtConfig: unknown): void => {
  const jwt = jwtConfig as JWTConfigCandidate;

  validateJWTConfigRequired(jwt);
  validateJWTConfigOptional(jwt);

  if (jwt.cookieOptions) validateCookieOptions(jwt.cookieOptions, "JWT cookie");

  if (jwt.refreshCookieOptions) validateCookieOptions(jwt.refreshCookieOptions, "JWT refresh cookie");
};

const validateCookieOptions = (options: unknown, type: string): void => {
  const opts = options as CookieOptionsCandidate;

  if (
    typeof opts.httpOnly !== "boolean" ||
    typeof opts.secure !== "boolean" ||
    !["Strict", "Lax", "None"].includes(opts.sameSite as string) ||
    typeof opts.maxAge !== "number" ||
    (opts.path !== undefined && typeof opts.path !== "string") ||
    (opts.domain !== undefined && typeof opts.domain !== "string")
  ) {
    throw new AuthKitError(`Invalid ${type} options`, "CONFIG_ERROR");
  }
};

const validateDatabaseConfig = (dbConfig: unknown): void => {
  const db = dbConfig as DatabaseConfigCandidate;

  if (
    typeof db.type !== "string" ||
    !["postgres", "mysql"].includes(db.type) ||
    typeof db.url !== "string" ||
    typeof db.username !== "string" ||
    typeof db.secret !== "string" ||
    (db.port !== undefined && typeof db.port !== "number") ||
    (db.database !== undefined && typeof db.database !== "string")
  ) {
    throw new AuthKitError("Invalid database configuration", "CONFIG_ERROR");
  }
};

const validatePasswordPolicy = (passwordPolicy: unknown): void => {
  const policy = passwordPolicy as PasswordPolicyCandidate;

  if (
    typeof policy.minLength !== "number" ||
    (policy.maxLength !== undefined && typeof policy.maxLength !== "number") ||
    typeof policy.requireUppercase !== "boolean" ||
    typeof policy.requireLowercase !== "boolean" ||
    typeof policy.requireNumbers !== "boolean" ||
    typeof policy.requireSpecialCharacters !== "boolean"
  ) {
    throw new AuthKitError("Invalid password policy configuration", "CONFIG_ERROR");
  }
};

const validateOAuthProviders = (oauthProviders: unknown[]): void => {
  if (!Array.isArray(oauthProviders)) {
    throw new AuthKitError("oauthProviders must be an array", "CONFIG_ERROR");
  }

  for (const provider of oauthProviders) {
    const p = provider as OAuthProviderCandidate;
    if (
      typeof p.name !== "string" ||
      typeof p.clientId !== "string" ||
      typeof p.clientSecret !== "string" ||
      typeof p.authorizationEndpoint !== "string" ||
      typeof p.tokenEndpoint !== "string" ||
      typeof p.redirectUri !== "string" ||
      !Array.isArray(p.scope) ||
      !p.scope.every((s: unknown) => typeof s === "string") ||
      typeof p.userInfoEndpoint !== "string"
    ) {
      throw new AuthKitError("Invalid OAuth provider configuration", "CONFIG_ERROR");
    }
  }
};

function assertConfig(input: unknown): asserts input is AuthKitConfig {
  if (!input || typeof input !== "object" || Array.isArray(input))
    throw new AuthKitError("Config must be a non-array object", "CONFIG_ERROR");
  
  const cfg = input as Partial<AuthKitConfig>;

  validateRequiredProperties(cfg);
  validateOptionalProperties(cfg);
  validateJWTConfig(cfg.jwtConfig);
  validateDatabaseConfig(cfg.databaseConfig);

  if (cfg.passwordPolicy) validatePasswordPolicy(cfg.passwordPolicy);

  if (cfg.oauthProviders) validateOAuthProviders(cfg.oauthProviders);
}
