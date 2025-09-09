import { NextFunction, Request, Response } from "express";
import { Config } from "../interfaces/config.interface";
import createLogger from "../lib/wintson.logger";

export default (config: Config) => {
  return function (req: Request, res: Response, next: NextFunction) {
    const logger = createLogger(config);

    if (!config.session?.enabled) {
      logger.warn("Session middleware: Session authentication is not enabled");
      return next(); // Skip if session is not enabled
    }

    // Check if session and user exist
    if (req.session && req.session.user) {
      // Check if the token type is 'access'
      if (req.session.user.type !== "access") {
        logger.warn(
          "Session middleware: Invalid session type - only 'access' sessions are allowed"
        );
        return res.status(403).json({ error: "Invalid session type" });
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
