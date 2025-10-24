/* eslint-disable @typescript-eslint/no-explicit-any */
import { Request, Response, Router } from "express";
import { Config } from "../interfaces/config.interface";
import createLogger from "../lib/wintson.logger";
import express from "express";
import apiResponse from "../utils/api-response";
import twoFactorAuth, {
  TransportNotFoundError,
} from "../utils/two-factor-auth";
import { createSessionPayload } from "../utils/session";

/**
 * Session Authentication Routes
 * Handles login, 2FA verification, and logout for session-based auth
 */
export default (router: Router, config: Config) => {
  if (!config.session) {
    throw new Error("Session authentication not configured");
  }

  const logger = createLogger(config);
  router.use(express.json());
  const prefix = config.session.prefix || "/auth/session";

  let twoFASetup: ReturnType<typeof twoFactorAuth> | null = null;
  if (config.twoFA?.enabled) {
    twoFASetup = twoFactorAuth(config.twoFA);
  }

  /**
   * Login Route (without 2FA)
   * Each login creates a new session (supports multiple sessions)
   */
  if (!twoFASetup) {
    router.post(`${prefix}/login`, async (req: Request, res: Response) => {
      const { username, password } = req.body;
      logger.info(`Session login attempt for user: ${username}`);

      // Validate input
      if (!username || !password) {
        logger.warn("Unauthorized: Missing username or password");
        return res
          .status(400)
          .json(apiResponse(400, "Username and password are required", false));
      }

      try {
        const user = await config.userService.loadUser(username);
        if (!user) {
          logger.warn(`Unauthorized: User not found (username: ${username})`);
          return res.status(401).json(apiResponse(401, "Unauthorized", false));
        }

        const validPassword = await config.passwordChecker(
          password,
          user.password
        );
        if (!validPassword) {
          logger.warn(`Unauthorized: Invalid password for user: ${username}`);
          return res.status(401).json(apiResponse(401, "Unauthorized", false));
        }

        // Prepare session payload
        const payload = {
          id: user.id,
          username: user.username,
          type: "access" as const,
          ...(user.grants && user.grants.length > 0 && { grants: user.grants }),
        };

        // Store user details in session
        req.session.user = payload;

        logger.info(`Session login successful for user: ${username}`);
        res.json(apiResponse(200, "Login successful", true, [payload]));
      } catch (error) {
        logger.error(`Session login error for username: ${username}`, {
          error,
        });
        res.status(500).json(apiResponse(500, "Internal server error", false));
      }
    });

    /**
     * Login Route with 2FA enabled
     * Generates OTP and stores session after verification
     */
  } else {
    router.post(`${prefix}/login`, async (req: Request, res: Response) => {
      try {
        if (!config.twoFA || !config.twoFA.enabled) {
          throw new Error("Two Factor Authentication is not enabled");
        }

        const { username } = req.body;
        if (!username) {
          return res
            .status(400)
            .json({ message: "Email required on request payload" });
        }

        const user = await config.userService.loadUser(username);
        if (!user) {
          logger.warn(`Invalid payload`);
          return res.status(401).json({ message: "Unauthorized" });
        }

        if (!user.is2faEnabled) {
          logger.warn("Two Factor Authentication is not enabled for the user");
          return res.status(401).json({
            error: "Unauthorized",
          });
        }

        // Initiate OTP generation
        await twoFASetup.initiate2fa(user);
        logger.info(`OTP Generated and transported succesfully`);
        res.status(200).json({
          message: "Send One Time Password for Two Factor Authentication",
        });
      } catch (error: any) {
        if (error instanceof TransportNotFoundError) {
          logger.warn(error.message);
          logger.error("OTP generated, but No Transport Available")
          return res
            .status(401)
            .json({ error: "Unauthorized" });
        }
        logger.error(`Two Factor Auth initalization Failed: ${error.message}`);
        res.status(500).json({
          error: "Something went wrong",
        });
      }
    });

    /**
     * OTP Verification Route
     * Verifies OTP and creates session for user
     */
    router.post(`${prefix}/verify`, async (req: Request, res: Response) => {
      const { otp, email } = req.body;
      if (!otp || !email) {
        return res.status(400).json({
          error: "Both 'otp' and 'email' are required in the request payload.",
        });
      }

      try {
        const user = await config.userService.loadUser(email);
        if (!user) {
          return res.status(401).json({ error: "Unauthorized" });
        }

        const isValid = await twoFASetup.verifyOtp(user, otp);
        if (!isValid) {
          return res.status(401).json({ error: "Unauthorized" });
        }

        logger.info("OTP Verified Successfully");

        // Create session payload after successful OTP verification
        const payload = createSessionPayload(user);
        req.session.user = payload;

        logger.info(`Session Login successful`);
        return res.json(apiResponse(201, "Login Successful", true, [payload]));
      } catch (error: any) {
        logger.error(error.message);
        res.status(500).json({ error: "Something went wrong" });
      }
    });
  }

  /**
   * Logout Route
   * Destroys current session and clears session cookie
   */
  router.post(`${prefix}/logout`, (req: Request, res: Response) => {
    logger.info("Session logout attempt received");

    // Handle case when no session exists
    if (!req.session || !req.session.user) {
      logger.info("Logout completed (no active session)");
      return res.json(apiResponse(200, "Logout successful", true));
    }

    const username = req.session.user.username;

    // Destroy session
    req.session.destroy((err) => {
      if (err) {
        logger.error("Error destroying session", { error: err });
        return res.status(500).json(apiResponse(500, "Something went wrong", false));
      }

      // Clear default session cookie
      res.clearCookie("connect.sid");

      logger.info(`Session logout successful for user: ${username}`);
      res.json(apiResponse(200, "Logout successful", true));
    });
  });
};
