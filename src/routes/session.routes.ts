import { Request, Response, Router } from "express";
import { Config } from "../interfaces/config.interface";
import createLogger from "../lib/wintson.logger";
import express from "express";
import apiResponse from "../utils/api-response";

export default (router: Router, config: Config) => {
  if (!config.session) {
    throw new Error("Session auth not configured");
  }

  const logger = createLogger(config);

  router.use(express.json());
  const prefix = config.session.prefix || "/auth/session";

  //Login Route
  router.post(`${prefix}/login`, async (req: Request, res: Response) => {
    const { username, password } = req.body;

    logger.info(` session login attempt `);
    try {
      const user = await config.userService.loadUser(username);
      if (!user) {
        logger.warn(`Login failed: User not found (username ${username})`);
        res
          .status(401)
          .json(apiResponse(401, "Invalid username or password", false));
      }

      const validPassword = await config.passwordChecker(
        password,
        user.password
      );
      if (!validPassword) {
        logger.warn(`Login failed: invalid password`);
        res
          .status(401)
          .json(apiResponse(401, "Invalid username or password", false));
      }
      const payload = {
        id: user.id,
        username: user.username,
        type: "access",
        ...(user.grands && user.grands.length > 0 && { grands: user.grands }), // Add only if user.grands exists and is not empty
      };
      // Store user details in session
      req.session.user = payload;

      logger.info(`session Login successfull `);
      res.json(apiResponse(201, "Login Successfull", true, [payload]));
    } catch (error) {
      logger.error(`session Login error for username ${username} `, error);
      res.status(500).json(apiResponse(500, "Internal server error", false));
    }
  });
};
