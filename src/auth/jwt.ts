import crypto from "node:crypto";
import { AuthKitError, type User } from "@luishutterli/auth-kit-types";
import type { Context, Next } from "hono";
import { getConfig } from "../config/config";
import { timingSafeCompare } from "../util/hash";
import { validateJWTCookie } from "./cookies";

const config = getConfig();
const { jwtConfig } = config;

// Types
export interface JWTHeader {
  alg: "HS256";
  typ: "jwt";
}

export interface JWTPayload {
  iss: string;
  sub: number;
  exp: number;
  nbf?: number;
  iat: number;
  user: User;
  ver?: number;
}

export interface JWT {
  header: JWTHeader;
  payload: JWTPayload;
  signature: string;
}

// Utils
const base64UrlEncode = (str: string): string => {
  return Buffer.from(str, "utf-8").toString("base64url");
};

const base64UrlDecode = (str: string): string => {
  return Buffer.from(str, "base64url").toString("utf-8");
};

const parseWrittenTimeToSeconds = (time: string | number): number => {
  if (typeof time === "number") return time;

  const match = RegExp(/^(\d+)([smhd])$/).exec(time);
  if (!match) throw new Error(`Invalid time format: ${time}`);

  const value = parseInt(match[1], 10);
  if (match[2].toLowerCase() === "s") return value;
  else if (match[2].toLowerCase() === "m") return value * 60;
  else if (match[2].toLowerCase() === "h") return value * 60 * 60;
  else if (match[2].toLowerCase() === "d") return value * 60 * 60 * 24;

  throw new AuthKitError(`Invalid time unit: ${match[2]}`, "INVALID_TIME");
};

export type JWTString = `${string}.${string}.${string}`;

export const JWTtoString = (jwt: JWT): JWTString => {
  const headerBase64 = base64UrlEncode(JSON.stringify(jwt.header));
  const payloadBase64 = base64UrlEncode(JSON.stringify(jwt.payload));
  return `${headerBase64}.${payloadBase64}.${jwt.signature}`;
};

export const stringToJWT = (jwt: JWTString): JWT => {
  const parts = jwt.split(".");
  if (parts.length !== 3)
    throw new AuthKitError("Invalid JWT format", "INVALID_JWT_FORMAT");

  const [headerB64, payloadB64, signature] = parts;

  try {
    const header: JWTHeader = JSON.parse(base64UrlDecode(headerB64));
    const payload: JWTPayload = JSON.parse(base64UrlDecode(payloadB64));
    return {
      header,
      payload,
      signature,
    };
  } catch (_) {
    throw new AuthKitError("Failed to parse JWT", "JWT_PARSE_ERROR", 400);
  }
};

// Create jwt's
const createHeader = (): JWTHeader => ({ alg: "HS256", typ: "jwt" });

const createPayload = (user: User, ver?: number): JWTPayload => {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: jwtConfig.issuer || config.name,
    sub: user.id,
    exp: now + parseWrittenTimeToSeconds(jwtConfig.expiresIn),
    iat: now,
    nbf: now,
    user,
    ver,
  };
};

const createSignature = (header: JWTHeader, payload: JWTPayload): string => {
  const headerBase64 = base64UrlEncode(JSON.stringify(header));
  const payloadBase64 = base64UrlEncode(JSON.stringify(payload));
  const data = `${headerBase64}.${payloadBase64}`;
  const secret = jwtConfig.secret;

  return crypto.createHmac("sha256", secret).update(data).digest("base64url");
};

export const createSignedJWT = (user: User, ver?: number): JWT => {
  const header = createHeader();
  const payload = createPayload(user, ver);
  const signature = createSignature(header, payload);

  return {
    header,
    payload,
    signature,
  };
};

export const validateJWT = (jwt: JWT | JWTString): boolean => {
  if (typeof jwt === "string") jwt = stringToJWT(jwt);
  const headerBase64 = base64UrlEncode(JSON.stringify(jwt.header));
  const payloadBase64 = base64UrlEncode(JSON.stringify(jwt.payload));
  const data = `${headerBase64}.${payloadBase64}`;
  const secret = jwtConfig.secret;

  const expectedSignature = crypto
    .createHmac("sha256", secret)
    .update(data)
    .digest("base64url");
  const matchingSignature = timingSafeCompare(expectedSignature, jwt.signature);
  if (!matchingSignature) return false;

  // Check validity
  const now = Math.floor(Date.now() / 1000);
  const { exp, nbf } = jwt.payload;
  if (exp && now >= exp) return false; // expired
  if (nbf && now < nbf) return false; // not yet valid

  // TODO: Validate JWT version!!

  return true;
};

// Middleware
export const jwtMiddleware = async (c: Context, next: Next) => {
  const validation = validateJWTCookie(c);
  if (!validation.valid)
    return c.json(
      { success: false, error: "Invalid or missing token for authentication" },
      401,
    );

  c.set("userId", validation.userId);
  c.set("jwt", validation.jwt);

  await next();
};
