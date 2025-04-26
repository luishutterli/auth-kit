import * as crypto from "node:crypto";
import type { JWTConfig, JWTPayload } from "@luishutterli/auth-kit-types";

const createHeader = (config: JWTConfig) => {
  return Buffer.from(
    JSON.stringify({
      alg: config.algorithm,
      typ: "JWT",
    }),
  ).toString("base64url");
};

const signPayload = (
  payload: string,
  header: string,
  secret: string,
  algorithm: string,
): string => {
  const data = `${header}.${payload}`;
  let signature: string;
  if (algorithm === "HMAC-SHA-256") {
    signature = crypto.createHmac("sha256", secret).update(data).digest("base64url");
  } else {
    throw new Error("Unsupported algorithm");
  }
  return signature;
};

export const generateToken = (payload: JWTPayload, config: JWTConfig): string => {
  const header = createHeader(config);
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = signPayload(encodedPayload, header, config.secret, config.algorithm);

  return `${header}.${encodedPayload}.${signature}`;
};

export const verifyToken = <T extends JWTPayload>(
  token: string,
  config: JWTConfig,
): T | null => {
  try {
    const [header, payload, signature] = token.split(".");

    const expectedSignature = signPayload(
      payload,
      header,
      config.secret,
      config.algorithm,
    );
    if (signature !== expectedSignature) {
      return null;
    }

    const decodedPayload = JSON.parse(
      Buffer.from(payload, "base64url").toString("utf-8"),
    ) as T;

    const currentTime = Math.floor(Date.now() / 1000);
    if (decodedPayload.exp < currentTime) {
      return null;
    }

    if (decodedPayload.nbf && decodedPayload.nbf > currentTime) {
      return null;
    }

    return decodedPayload;
  } catch (error) {
    return null;
  }
};
