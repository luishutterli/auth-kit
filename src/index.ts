import { Hono } from "hono";
import { setCookie } from "hono/cookie";
import type { AuthKitConfig, User } from "@luishutterli/auth-kit-types";
import {
  AuthKitError,
  AuthenticationError,
  DatabaseError,
} from "@luishutterli/auth-kit-types";
import { AuthService } from "./services/auth.service";
import { OrganizationService } from "./services/organization.service";
import { authenticate, getUser } from "./middleware/auth.middleware";
import { initializeDatabase } from "./utils/db-init";
import type { UnofficialStatusCode } from "hono/utils/http-status";

export async function createAuthRouter(config: AuthKitConfig) {
  await initializeDatabase(config.databaseConfig, config.autoCreateSchema);

  const authService = new AuthService(config);
  const orgService = new OrganizationService();

  const app = new Hono();

  app.basePath(config.baseUrl);

  app.use("*", async (c, next) => {
    try {
      await next();
    } catch (error) {
      if (error instanceof AuthKitError) {
        return c.json(error.toJSON(), error.statusCode as UnofficialStatusCode);
      }
      return c.json({ error: "Internal server error" }, 500);
    }
  });

  app.get("/", (c) => {
    return c.json({ status: "ok", service: config.name });
  });

  app.post("/signup", async (c) => {
    try {
      const body = await c.req.json();
      const { email, password, name, surname } = body;

      if (!email || !password || !name || !surname) {
        throw new AuthenticationError("Missing required fields", 400);
      }

      const result = await authService.signup(email, password, name, surname);

      if (
        config.jwtConfig.jwtStorageLocation === "cookie" &&
        config.jwtConfig.cookieName
      ) {
        setCookie(
          c,
          config.jwtConfig.cookieName,
          result.accessToken,
          config.jwtConfig.cookieOptions,
        );
      }

      const { accessToken, refreshToken, ...resultWithoutTokens } = result;
      return c.json(resultWithoutTokens);
    } catch (error) {
      if (error instanceof AuthKitError) {
        throw error;
      }
      throw new DatabaseError("Signup failed", error as Error);
    }
  });

  app.post("/login", async (c) => {
    try {
      const body = await c.req.json();
      const { email, password } = body;

      if (!email || !password) {
        throw new AuthenticationError("Missing email or password", 400);
      }

      const ip = c.req.header("x-forwarded-for") ?? c.req.header("x-real-ip") ?? "na"; // TODO: get ip
      const userAgent = c.req.header("user-agent") ?? "unknown";

      const result = await authService.login(email, password, ip, userAgent);

      if (
        config.jwtConfig.jwtStorageLocation === "cookie" &&
        config.jwtConfig.cookieName
      ) {
        setCookie(
          c,
          config.jwtConfig.cookieName,
          result.accessToken,
          config.jwtConfig.cookieOptions,
        );
      }

      const { accessToken, refreshToken, ...resultWithoutTokens } = result;
      return c.json(resultWithoutTokens);
    } catch (error) {
      if (error instanceof AuthKitError) {
        throw error;
      }
      throw new DatabaseError("Login failed", error as Error);
    }
  });

  app.post("/refresh", async (c) => {
    try {
      const body = await c.req.json();
      const { refreshToken } = body;

      if (!refreshToken) {
        throw new AuthenticationError("Missing refresh token", 400);
      }

      const result = await authService.refreshToken(refreshToken);

      if (
        config.jwtConfig.jwtStorageLocation === "cookie" &&
        config.jwtConfig.cookieName
      ) {
        setCookie(
          c,
          config.jwtConfig.cookieName,
          result.accessToken,
          config.jwtConfig.cookieOptions,
        );
      }

      const { accessToken, refreshToken: _, ...resultWithoutTokens } = result;
      return c.json(resultWithoutTokens);
    } catch (error) {
      if (error instanceof AuthKitError) {
        throw error;
      }
      throw new DatabaseError("Token refresh failed", error as Error);
    }
  });

  app.get("/me", authenticate(config, authService), async (c) => {
    try {
      const user = getUser(c);
      return c.json({ user });
    } catch (error) {
      if (error instanceof AuthKitError) {
        throw error;
      }
      throw new DatabaseError("Failed to get user info", error as Error);
    }
  });

  app.post("/org/create", authenticate(config, authService), async (c) => {
    try {
      const user = getUser(c);
      const body = await c.req.json();
      const { orgName } = body;

      if (!orgName) {
        throw new AuthenticationError("Organization name is required", 400);
      }

      const organization = await orgService.createOrganization(orgName, user.id);

      return c.json({ organization });
    } catch (error) {
      if (error instanceof AuthKitError) {
        throw error;
      }
      throw new DatabaseError("Failed to create organization", error as Error);
    }
  });

  return app;
}
