import type { Context } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import { getConfig } from "../config/config";
import {
  type JWT,
  type JWTString,
  JWTtoString,
  stringToJWT,
  validateJWT,
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

export const addJWTCookie = (c: Context, jwt: JWT): void =>
  setCookie(c, jwtConfig.cookieName ?? "authkit_token", JWTtoString(jwt), {
    ...cookieOptions,
  });

export const removeJWTCookie = (c: Context): void => {
  deleteCookie(c, jwtConfig.cookieName ?? "authkit_token");
};

export const validateJWTCookie = (
  c: Context,
): { valid: boolean; jwt?: JWT, userId?: number } => {
  const token = getCookie(c, jwtConfig.cookieName ?? "authkit_token");
  if (!token) return { valid: false };

  const jwt = stringToJWT(token as JWTString);
  const success = validateJWT(jwt);
  if (!success) return { valid: false };
  return { valid: true, jwt, userId: jwt.payload.sub };
};
