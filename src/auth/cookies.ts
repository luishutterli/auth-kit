import type { Context } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import { getConfig } from "../config/config";
import {
  type JWT,
  type JWTString,
  JWTtoString,
  stringToJWT,
  validateAccessToken,
  validateRefreshToken,
} from "./jwt";

const config = getConfig();
const { jwtConfig } = config;
const cookieOptions = jwtConfig?.cookieOptions ?? {
  httpOnly: true,
  secure: true,
  sameSite: "Strict",
  maxAge: 60 * 60,
  path: "/",
};

const refreshCookieOptions = jwtConfig?.refreshCookieOptions ?? {
  ...cookieOptions,
  maxAge: 60 * 60 * 24 * 7,
};

export const addJWTCookie = (c: Context, jwt: JWT): void =>
  setCookie(c, jwtConfig.cookieName ?? "authkit_token", JWTtoString(jwt), {
    ...cookieOptions,
  });

export const removeJWTCookie = (c: Context): void => {
  deleteCookie(c, jwtConfig.cookieName ?? "authkit_token");
};

export const validateJWTCookie = (
  c: Context,
): { valid: boolean; jwt?: JWT; userId?: number } => {
  const token = getCookie(c, jwtConfig.cookieName ?? "authkit_token");
  if (!token) return { valid: false };

  const jwt = stringToJWT(token as JWTString);
  const success = validateAccessToken(jwt);
  if (!success) return { valid: false };
  return { valid: true, jwt, userId: jwt.payload.sub };
};

export const addRefreshTokenCookie = (c: Context, jwt: JWT): void =>
  setCookie(c, jwtConfig.refreshCookieName ?? "authkit_refresh", JWTtoString(jwt), {
    ...refreshCookieOptions,
  });

export const removeRefreshTokenCookie = (c: Context): void => {
  deleteCookie(c, jwtConfig.refreshCookieName ?? "authkit_refresh");
};

export const validateRefreshTokenCookie = (
  c: Context,
): { valid: boolean; jwt?: JWT; userId?: number } => {
  const token = getCookie(c, jwtConfig.refreshCookieName ?? "authkit_refresh");
  if (!token) return { valid: false };

  const jwt = stringToJWT(token as JWTString);
  const success = validateRefreshToken(jwt);
  if (!success) return { valid: false };
  return { valid: true, jwt, userId: jwt.payload.sub };
};

export const setTokenPair = (c: Context, accessToken: JWT, refreshToken: JWT): void => {
  addJWTCookie(c, accessToken);
  addRefreshTokenCookie(c, refreshToken);
};

export const clearTokenPair = (c: Context): void => {
  removeJWTCookie(c);
  removeRefreshTokenCookie(c);
};
