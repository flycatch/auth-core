import { Request, Response, Router } from "express";
import { Config } from "../interfaces/config.interface";
import createLogger from "../lib/wintson.logger";
import express from "express";
import apiResponse from "../utils/api-response";
import twoFactorAuth, {
  InvalidOtpError,
  OtpExpiredError,
  TransportNotFoundError,
} from "../utils/two-factor-auth";
import { createSessionPayload } from "../utils/session";

// Extend session interface

export default (router: Router, config: Config) => {
  if (!config.session) {
    throw new Error("Session authentication not configured");
  }

  const logger = createLogger(config);
  router.use(express.json());
  const prefix = config.session.prefix || "/auth/session";

  const { initiate2fa, verifyOtp } = twoFactorAuth(config.twoFA);

  // Login Route - Each login creates a new session (supports multiple sessions)
  if (!config.twoFA?.enabled) {
    router.post(`${prefix}/login`, async (req: Request, res: Response) => {
      const { username, password } = req.body;
      logger.info(`Session login attempt for user: ${username}`);

      // Validate input
      if (!username || !password) {
        logger.warn("Login failed: Missing username or password");
        return res
          .status(400)
          .json(apiResponse(400, "Username and password are required", false));
      }

      try {
        const user = await config.userService.loadUser(username);
        if (!user) {
          logger.warn(`Login failed: User not found (username: ${username})`);
          return res.status(401).json(apiResponse(401, "Login Failed", false));
        }

        const validPassword = await config.passwordChecker(
          password,
          user.password
        );
        if (!validPassword) {
          logger.warn(`Login failed: Invalid password for user: ${username}`);
          return res.status(401).json(apiResponse(401, "Login Failed", false));
        }

        const payload = {
          id: user.id,
          username: user.username,
          type: "access" as const,
          // Fix the typo: should be 'grants' not 'grands'
          ...(user.grants && user.grants.length > 0 && { grants: user.grants }),
        };

        // Store user details in session - this creates a new session each time
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
          return res.status(404).json({ message: "Login Failed" });
        }

        if (!user.is2faEnabled) {
          logger.warn("Two Factor Authentication is not enabled for the user");
          return res.status(403).json({
            error: "Two Factor Authentication is not enabled for the user",
          });
        }

        await initiate2fa(user);
        logger.info(`OTP Generated and transported succesfully`);
        res.status(200).json({
          message: "Send One Time Password for Two Factor Authentication",
        });
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      } catch (error: any) {
        if (error instanceof TransportNotFoundError) {
          logger.warn(error.message);
          return res
            .status(500)
            .json({ error: "OTP generated, but No Transport Available" });
        }
        logger.error(`Two Factor Auth initalization Failed: ${error.message}`);
        res.status(500).json({
          error: "Two Factor Auth initalization Failed",
        });
      }
    });

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
          return res.status(401).json({ error: "Invalid User" });
        }

        const isValid = await verifyOtp(user, otp);
        if (!isValid) {
          res.status(401).json({ error: "Invalid OTP" });
        }

        logger.info("OTP Verified Successfully");
        // Issue JWT or session

        const payload = createSessionPayload(user);
        // Store user details in session
        req.session.user = payload;

        logger.info(`Session Login successful `);
        return res.json(apiResponse(201, "Login Successful", true, [payload]));

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      } catch (error: any) {
        if (error instanceof OtpExpiredError || InvalidOtpError) {
          logger.warn(error.message);
          return res.status(401).json({ error: error.message });
        }
        logger.error(error.message);
        res.status(500).json({ error: error.message });
      }
    });
  }

  // Logout Route - Simple logout that destroys current session
  router.post(`${prefix}/logout`, (req: Request, res: Response) => {
    logger.info("Session logout attempt received");

    // If no session exists, still return success (client-side cleanup)
    if (!req.session || !req.session.user) {
      logger.info("Logout completed (no active session)");
      return res.json(apiResponse(200, "Logout successful", true));
    }

    const username = req.session.user.username;

    // Destroy the session
    req.session.destroy((err) => {
      if (err) {
        logger.error("Error destroying session", { error: err });
        return res.status(500).json(apiResponse(500, "Logout failed", false));
      }

      // Clear the session cookie
      res.clearCookie("connect.sid"); // Default session cookie name

      logger.info(`Session logout successful for user: ${username}`);
      res.json(apiResponse(200, "Logout successful", true));
    });
  });
};
