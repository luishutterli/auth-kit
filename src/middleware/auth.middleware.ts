import type { Context, Next } from "hono";
import type { AuthService } from "../services/auth.service";
import { getCookie } from "hono/cookie";
import type { AuthKitConfig, User } from "@luishutterli/auth-kit-types";
import {
  AuthenticationError,
  AuthKitError,
  AuthorizationError,
} from "@luishutterli/auth-kit-types";

const extractToken = (c: Context, config: AuthKitConfig): string | null => {
  if (config.jwtConfig.jwtStorageLocation === "cookie") {
    if (!config.jwtConfig.cookieName) {
      throw new AuthKitError("Cookie name is not defined in the config", "CONFIG_ERROR");
    }
    const cookieName = config.jwtConfig.cookieName;
    const token = getCookie(c, cookieName);
    if (token) {
      return token;
    }
  }

  return null;
};

export const authenticate = (config: AuthKitConfig, authService: AuthService) => {
  return async (c: Context, next: Next) => {
    const token = extractToken(c, config);

    if (!token) {
      throw new AuthenticationError("Unauthorized - No token provided");
    }

    const user = await authService.validateToken(token);

    if (!user) {
      throw new AuthenticationError("Unauthorized - Invalid token");
    }

    if (config.enforceVerifiedEmail && !user.emailVerified) {
      throw new AuthorizationError("Email verification required");
    }

    c.set("user", user);

    await next();
  };
};

export const getUser = (c: Context): User => {
  const user = c.get("user");
  if (!user) {
    throw new AuthenticationError("User not found in context");
  }
  return user as User;
};
