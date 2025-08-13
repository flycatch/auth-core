import crypto from "crypto";
import ms from "ms"; // Optional dep for parsing '5m' to ms; add if not present
import { Config } from "../interfaces/config.interface";

// Pure: Generate random OTP
const generateOtp = (length: number): string =>
  crypto
    .randomBytes(length / 2)
    .toString("hex")
    .padStart(length, "0"); // Ensure numeric, fixed length

// Higher-order: Create configured handlers

export const create2faHandlers = (config: Config["twoFA"]) => {
  if (!config) {
    throw new Error("No configuration added for 2FA");
  }
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const isEnabledForUser = (user: any): boolean =>
    config.enabled && user.is2faEnabled;

  // Impure (side effects): Initiate 2FA flow
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const initiate2fa = async (user: any): Promise<void> => {
    if (!isEnabledForUser(user)) return;

    const otp = generateOtp(config.otpLength);
    const expiresInMs = ms(config.otpExpiresIn);

    if (config.onOtpGenerated) await config.onOtpGenerated(otp, user);

    await config.storeOtp(user.id, otp, expiresInMs);

    try {
      await config.transport(otp, user);
      if (config.onOtpSent) await config.onOtpSent(user);
    } catch (err) {
      throw new TransportError(`Failed to send OTP: ${err}`);
    }
  };

  // Impure: Verify OTP
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const verifyOtp = async (user: any, inputOtp: string): Promise<boolean> => {
    if (!isEnabledForUser(user)) throw new Error("2FA not enabled");

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

    await config.clearOtp(user.id);
    if (config.onVerifySuccess) await config.onVerifySuccess(user);
    return true;
  };

  return { initiate2fa, verifyOtp };
};

// Custom errors for handling
export class OtpExpiredError extends Error {}
export class InvalidOtpError extends Error {}
export class TransportError extends Error {}
