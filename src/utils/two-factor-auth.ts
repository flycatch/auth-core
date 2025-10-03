import crypto from "crypto";
import ms from "ms"; // Optional dep for parsing '5m' to ms; add if not present
import { Config } from "../interfaces/config.interface";
import { User } from "../interfaces/user.interface";

/**Function to generate otp with provided length and type (numeric and alphanumeric types are suppoted) */
export function generateOtp(
  length: number = 6,
  format: "numeric" | "alphanumeric"
): string {
  let chars = "";
  switch (format) {
    case "numeric":
      chars = "0123456789";
      break;
    case "alphanumeric":
      chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
      break;
    default:
      throw new Error("Invalid OTP format");
  }
  return Array.from(crypto.randomBytes(length))
    .map((byte) => chars[byte % chars.length])
    .join("");
}

// Higher-order: Create configured handlers

export default (config: Config["twoFA"]) => {
  if (!config) {
    throw new Error("No configuration added for 2FA");
  }

  // Impure (side effects): Initiate 2FA flow
  const initiate2fa = async (user: User): Promise<void> => {
    const otp = generateOtp(
      config.otpLength ? config.otpLength : 6,
      config.otpType ? config.otpType : "numeric"
    );
    const rawExpiresIn = config.otpExpiresIn ?? "5m";

    const expiresInMs =
      typeof rawExpiresIn === "number"
        ? rawExpiresIn
        : (ms(rawExpiresIn) as number);

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

  // Impure: Verify OTP
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

// Custom errors for handling
export class OtpExpiredError extends Error {}
export class InvalidOtpError extends Error {}
export class TransportNotFoundError extends Error {}
