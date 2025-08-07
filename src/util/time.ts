import { AuthKitError } from "@luishutterli/auth-kit-types";

/**
 * Parses a time string to seconds
 * @param time - Time string s, m, h, d
 * @returns Number of seconds
 */
export const parseTimeToSeconds = (time: string | number): number => {
  if (typeof time === "number") return time;

  const match = /^(\d+)([smhd])$/.exec(time);
  if (!match) {
    throw new AuthKitError(`Invalid time format: ${time}. Expected format: <number>[s|m|h|d]`, "INVALID_TIME_FORMAT");
  }

  const value = parseInt(match[1], 10);
  const unit = match[2].toLowerCase();

  switch (unit) {
    case "s":
      return value;
    case "m":
      return value * 60;
    case "h":
      return value * 60 * 60;
    case "d":
      return value * 60 * 60 * 24;
    default:
      throw new AuthKitError(`Invalid time unit: ${unit}`, "INVALID_TIME_UNIT");
  }
};
