import { getConfig } from "../config/config";

const config = getConfig();

const passwordPolicy = config.passwordPolicy ?? {
  minLength: 8,
  maxLength: 64,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecialCharacters: true,
};

if (passwordPolicy.maxLength && passwordPolicy.minLength > passwordPolicy.maxLength) {
  throw new Error(
    `Invalid password policy: minLength (${passwordPolicy.minLength}) cannot be greater than maxLength (${passwordPolicy.maxLength})`
  );
}

export const validatePasswordWithError = (password: string): string | null => {
  if (password.length < passwordPolicy.minLength) {
    return `Password must be at least ${passwordPolicy.minLength} characters long`;
  }
  if (passwordPolicy.maxLength && password.length > passwordPolicy.maxLength) {
    return `Password must be at most ${passwordPolicy.maxLength} characters long`;
  }
  if (passwordPolicy.requireUppercase && !/[A-Z]/.test(password)) {
    return "Password must contain at least one uppercase letter";
  }
  if (passwordPolicy.requireLowercase && !/[a-z]/.test(password)) {
    return "Password must contain at least one lowercase letter";
  }
  if (passwordPolicy.requireNumbers && !/\d/.test(password)) {
    return "Password must contain at least one number";
  }
  if (
    passwordPolicy.requireSpecialCharacters &&
    !/[!@#$%^&*()_\-+={}[\]\\|;:"'<>,.?/~`]/.test(password)
  ) {
    return "Password must contain at least one special character";
  }
  return null;
};
