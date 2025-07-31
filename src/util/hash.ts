import crypto from "node:crypto";
import { AuthKitError } from "@luishutterli/auth-kit-types";
import { getConfig } from "../config/config";

const config = getConfig();
const { passwordHashAlgorithm, passwordSaltLength } = config;

const generateSalt = (): string => {
	return crypto.randomBytes(passwordSaltLength).toString("hex");
};

const hashPassword = (password: string, salt: string): string => {
	const toHash = `${password}${salt}`;
	const hash = crypto.createHash(passwordHashAlgorithm).update(toHash);
	return hash.digest("hex");
};

const timingSafeCompare = (a: string, b: string): boolean => {
	if (a.length !== b.length) return false;
	const aBuffer = Buffer.from(a, "hex");
	const bBuffer = Buffer.from(b, "hex");
	return crypto.timingSafeEqual(aBuffer, bBuffer);
};

export const generateDBHash = (password: string): string => {
	const salt = generateSalt();
	return hashPassword(password, salt) + salt;
};

export const verifyPassword = (
	dbHash: string,
	providedPassword: string,
): boolean => {
	if (dbHash.length !== 192) {
		throw new AuthKitError(
			"Provided hash and salt combo value is of invalid length. Currently only a length of 192 is supported.",
			"HASH_INVALID_LENGTH",
			500,
		);
	}
  const hash = dbHash.slice(0, 128);
	const salt = dbHash.slice(128, 192);
	return timingSafeCompare(hash, hashPassword(providedPassword, salt));
};

/**
 * 
 * @returns Always returns false
 */
export const dummyHashVerify = (): boolean => {
  const salt = generateSalt();
  const dummyDBhash = hashPassword("abcdefghijklmnopqrstuvwxyz", salt) + salt;

  return verifyPassword(dummyDBhash, "zyxwvutsrqponmlkjihgfedcba");
}