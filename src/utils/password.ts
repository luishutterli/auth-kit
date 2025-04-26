import * as crypto from "node:crypto";
import {
  NotFoundError,
  type AuthKitConfig,
  type PasswordPolicy,
} from "@luishutterli/auth-kit-types";

const generateSalt = (length: number): string => {
  return crypto.randomBytes(length).toString("hex");
};

export const hashPassword = (password: string, config: AuthKitConfig): string => {
  const salt = generateSalt(config.passwordSaltLength / 8);
  let hash: string;

  if (config.passwordHashAlgorithm === "SHA-512") {
    hash = crypto
      .createHash("sha512")
      .update(password + salt)
      .digest("hex");
  } else {
    throw new NotFoundError(
      `Password hashing algorithm ${config.passwordHashAlgorithm} not implemented`,
    );
  }

  const type = config.passwordHashAlgorithm === "SHA-512" ? "512" : null;

  return `${type}:${salt}:${hash}`;
};

export const verifyPassword = (
  password: string,
  storedHash: string,
  config: AuthKitConfig,
): boolean => {
  const [type, salt, hash] = storedHash.split(":");
  let calculatedHash: string;

  if (config.passwordHashAlgorithm === "SHA-512" && type === "512") {
    calculatedHash = crypto
      .createHash("sha512")
      .update(password + salt)
      .digest("hex");
  } else {
    throw new NotFoundError(
      `Password hashing algorithm ${config.passwordHashAlgorithm} not implemented or not matching type ${type}`,
    );
  }

  return calculatedHash === hash;
};

export const validatePassword = (
  password: string,
  policy: PasswordPolicy,
): { valid: boolean; message?: string } => {
  if (password.length < policy.minLength) {
    return {
      valid: false,
      message: `Password must be at least ${policy.minLength} characters long`,
    };
  }

  if (policy.maxLength && password.length > policy.maxLength) {
    return {
      valid: false,
      message: `Password must be no more than ${policy.maxLength} characters long`,
    };
  }

  if (policy.requireUppercase && !/[A-Z]/.test(password)) {
    return {
      valid: false,
      message: "Password must contain at least one uppercase letter",
    };
  }

  if (policy.requireLowercase && !/[a-z]/.test(password)) {
    return {
      valid: false,
      message: "Password must contain at least one lowercase letter",
    };
  }

  if (policy.requireNumbers && !/[0-9]/.test(password)) {
    return {
      valid: false,
      message: "Password must contain at least one number",
    };
  }

  return { valid: true };
};
