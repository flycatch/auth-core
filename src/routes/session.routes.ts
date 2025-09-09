import { Request, Response, Router } from "express";
import { Config } from "../interfaces/config.interface";
import createLogger from "../lib/wintson.logger";
import express from "express";
import apiResponse from "../utils/api-response";

// Extend session interface

export default (router: Router, config: Config) => {
  if (!config.session) {
    throw new Error("Session authentication not configured");
  }

  const logger = createLogger(config);
  router.use(express.json());
  const prefix = config.session.prefix || "/auth/session";

  // Login Route - Each login creates a new session (supports multiple sessions)
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
        return res
          .status(401)
          .json(apiResponse(401, "Invalid username or password", false));
      }

      const validPassword = await config.passwordChecker(
        password,
        user.password
      );
      if (!validPassword) {
        logger.warn(`Login failed: Invalid password for user: ${username}`);
        return res
          .status(401)
          .json(apiResponse(401, "Invalid username or password", false));
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
      logger.error(`Session login error for username: ${username}`, { error });
      res.status(500).json(apiResponse(500, "Internal server error", false));
    }
  });

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
