import crypto from "node:crypto";
import { AuthKitError, type JWTPayload, type User } from "@luishutterli/auth-kit-types";
import type { Context, Next } from "hono";
import { createMiddleware } from "hono/factory";
import type { RowDataPacket } from "mysql2";
import { getConfig } from "../config/config";
import { getConnection } from "../db/connection";
import { timingSafeCompare } from "../util/hash";
import { parseTimeToSeconds } from "../util/time";
import { setTokenPair, validateJWTCookie, validateRefreshTokenCookie } from "./cookies";

const config = getConfig();
const { jwtConfig } = config;

// Types
export interface JWTHeader {
  alg: "HS256";
  typ: "jwt";
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
    exp: now + parseTimeToSeconds(jwtConfig.expiresIn),
    iat: now,
    nbf: now,
    type: "access",
    user,
    ver,
  };
};

const createRefreshPayload = (userId: number, ver?: number): JWTPayload => {
  const now = Math.floor(Date.now() / 1000);
  const refreshExpiresIn = jwtConfig.refreshExpiresIn || "7d";
  return {
    iss: jwtConfig.issuer || config.name,
    sub: userId,
    exp: now + parseTimeToSeconds(refreshExpiresIn),
    iat: now,
    nbf: now,
    type: "refresh",
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

export const createRefreshToken = (userId: number, ver?: number): JWT => {
  const header = createHeader();
  const payload = createRefreshPayload(userId, ver);
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

  return true;
};

export const validateAccessToken = (jwt: JWT | JWTString): boolean => {
  if (!validateJWT(jwt)) return false;
  const jwtObj = typeof jwt === "string" ? stringToJWT(jwt) : jwt;
  return jwtObj.payload.type === "access";
};

export const validateRefreshToken = (jwt: JWT | JWTString): boolean => {
  if (!validateJWT(jwt)) return false;
  const jwtObj = typeof jwt === "string" ? stringToJWT(jwt) : jwt;
  return jwtObj.payload.type === "refresh";
};

export const extractUserId = (jwt: JWT | JWTString): number | null => {
  try {
    const jwtObj = typeof jwt === "string" ? stringToJWT(jwt) : jwt;
    return jwtObj.payload.sub;
  } catch {
    return null;
  }
};

// Middleware
export const jwtMiddleware = createMiddleware<{
  Variables: { userId: number; jwt: JWT; refreshed: boolean };
}>(async (c: Context, next: Next) => {
  const validation = validateJWTCookie(c);

  if (validation.valid) {
    c.set("userId", validation.userId);
    c.set("jwt", validation.jwt);
    c.set("refreshed", false);
    await next();
    return;
  }

  const refreshValidation = validateRefreshTokenCookie(c);
  if (!refreshValidation.valid) {
    return c.json(
      { success: false, error: "Invalid or missing token for authentication" },
      401,
    );
  }

  const connection = await getConnection();
  try {
    const [users] = await connection.execute<
      RowDataPacket[] &
        {
          accId: number;
          accEmail: string;
          accName: string;
          accSurname: string;
          accEmailVerified: number;
          accCreated: Date;
        }[]
    >(
      "SELECT accId, accEmail, accName, accSurname, accEmailVerified, accCreated FROM TAccounts WHERE accId = ? AND accStatus = 'active'",
      [refreshValidation.userId],
    );

    if (users.length === 0) {
      return c.json({ success: false, error: "User not found or inactive" }, 401);
    }

    const userRow = users[0];
    const user: User = {
      id: userRow.accId,
      email: userRow.accEmail,
      name: userRow.accName,
      surname: userRow.accSurname,
      emailVerified: userRow.accEmailVerified === 1,
      createdAt: userRow.accCreated,
      twoFactorEnabled: false,
    };

    const newAccessToken = createSignedJWT(user);
    const newRefreshToken = createRefreshToken(user.id);
    setTokenPair(c, newAccessToken, newRefreshToken);

    c.set("userId", user.id);
    c.set("jwt", newAccessToken);
    c.set("refreshed", true);

    await next();
  } catch (_error) {
    return c.json({ success: false, error: "Authentication refresh failed" }, 401);
  } finally {
    connection.release();
  }
});
