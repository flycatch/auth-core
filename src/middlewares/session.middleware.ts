import { NextFunction, Request, Response } from "express";
import { Config } from "../interfaces/config.interface";
import createLogger from "../lib/winston.logger";

/**
 * Express middleware for validating user sessions.
 *
 * This middleware checks if session authentication is enabled, verifies
 * the session exists, and ensures the session type is 'access'. It attaches
 * the session user to the request object for downstream handlers.
 *
 * @param {Config} config - Application configuration containing session settings.
 * @returns {import("express").RequestHandler} Express middleware function.
 */
export default (config: Config) => {
  return function (req: Request, res: Response, next: NextFunction) {
    const logger = createLogger(config);

    if (!config.session?.enabled) {
      logger.warn("Session middleware: Session authentication is not enabled");
      return next();
    }

    if (req.session && req.session.user) {
      if (req.session.user.type !== "access") {
        logger.warn(
          "Session middleware: Invalid session type - only 'access' sessions are allowed"
        );
        return res.status(401).json({ error: "Unauthorized" });
      }

      logger.info(
        `Session middleware: Access granted to user: ${req.session.user.username}`
      );
      req.user = req.session.user;
      return next();
    }

    logger.warn(
      "Session middleware: Unauthorized access attempt (session missing)"
    );
    return res.status(401).json({ error: "Unauthorized" });
  };
};
