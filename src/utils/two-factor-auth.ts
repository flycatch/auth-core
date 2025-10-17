import crypto from "crypto";
import ms from "ms"; // Optional dep for parsing '5m' to ms; add if not present
import { Config } from "../interfaces/config.interface";
import { User } from "../interfaces/user.interface";

/**
 * Generates a One-Time Password (OTP) of given length and format.
 *
 * @param {number} [length=6] - Length of the OTP to generate.
 * @param {"numeric" | "alphanumeric"} format - Format of the OTP.
 * @returns {string} Generated OTP string.
 * @throws {Error} Throws if an invalid format is provided.
 */
function generateOtp(
  length: number = 6,
  format: "numeric" | "alphanumeric"
): string {
  let chars = "";
  switch (format) {
    case "numeric":
      chars = "0123456789";
      break;
    case "alphanumeric":
      chars =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
      break;
    default:
      throw new Error("Invalid OTP format");
  }
  return Array.from(crypto.randomBytes(length))
    .map((byte) => chars[byte % chars.length])
    .join("");
}

/**
 * Creates 2FA handlers for initiating and verifying OTPs.
 *
 * @param {Config["twoFA"]} config - Two Factor Authentication configuration.
 * @returns {{
 *   initiate2fa: (user: User) => Promise<void>,
 *   verifyOtp: (user: User, inputOtp: string) => Promise<boolean>
 * }} Object containing initiate2fa and verifyOtp functions.
 * @throws {Error} Throws if configuration is missing or incomplete.
 */
export default (config: Config["twoFA"]) => {
  if (!config) {
    throw new Error("No configuration added for 2FA");
  }

  /**
   * Initiates a 2FA flow for a user by generating and sending OTP.
   *
   * @param {User} user - User object for whom OTP is generated.
   * @returns {Promise<void>}
   * @throws {TransportNotFoundError|Error} Throws if transport is not configured or sending fails.
   */
  const initiate2fa = async (user: User): Promise<void> => {
    const otp = generateOtp(
      config.otpLength ? config.otpLength : 6,
      config.otpType ? config.otpType : "numeric"
    );
    const rawExpiresIn = config.otpExpiresIn ?? "5m";

    const expiresInMs =
      typeof rawExpiresIn === "number" ? rawExpiresIn : (ms(rawExpiresIn) as number);

    if (config.onOtpGenerated) await config.onOtpGenerated(otp, user);

    if (!config.storeOtp) {
      throw new Error("Store OTP Logic should provide if 2fa is enabled");
    }

    await config.storeOtp(user.id, otp, expiresInMs);

    if (!config.transport) {
      throw new TransportNotFoundError(
        "No transport had been configured to send OTP, check your storage for the generated 2fa otp"
      );
    }

    try {
      await config.transport(otp, user);
      if (config.onOtpSent) await config.onOtpSent(user);
    } catch (err) {
      throw new Error(`Failed to send OTP: ${err}`);
    }
  };

  /**
   * Verifies a user's OTP input against the stored OTP.
   *
   * @param {User} user - User object for whom OTP is verified.
   * @param {string} inputOtp - OTP input provided by the user.
   * @returns {Promise<boolean>} Returns true if OTP is valid.
   * @throws {OtpExpiredError|InvalidOtpError|Error} Throws on invalid or expired OTP or missing config.
   */
  const verifyOtp = async (user: User, inputOtp: string): Promise<boolean> => {
    if (!config.getStoredOtp) {
      throw new Error("Need to config getStoredOtp logic for otp verification");
    }

    const storedOtp = await config.getStoredOtp(user.id);
    if (!storedOtp) {
      const error = new OtpExpiredError("OTP expired or invalid");
      if (config.onVerifyFail) await config.onVerifyFail(user, error);
      throw error;
    }

    if (storedOtp !== inputOtp) {
      const error = new InvalidOtpError("Invalid OTP");
      if (config.onVerifyFail) await config.onVerifyFail(user, error);
      throw error;
    }

    if (config.clearOtp) await config.clearOtp(user.id);
    if (config.onVerifySuccess) await config.onVerifySuccess(user);
    return true;
  };

  return { initiate2fa, verifyOtp };
};

/** Custom error thrown when OTP has expired or is invalid */
export class OtpExpiredError extends Error {}

/** Custom error thrown when OTP input does not match the stored OTP */
export class InvalidOtpError extends Error {}

/** Custom error thrown when no transport is configured to send OTP */
export class TransportNotFoundError extends Error {}
