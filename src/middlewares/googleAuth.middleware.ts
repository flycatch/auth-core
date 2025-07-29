import jwt from "jsonwebtoken";
import createLogger from "../lib/wintson.logger";
import { Config } from "../interfaces/config.interface";
import { NextFunction, Request, Response } from "express";
import { JWTPayload } from "../interfaces/jwt.interface";

export default (config: Config) => {
  return function (req: Request, res: Response, next: NextFunction) {
    const logger = createLogger(config);

    logger.info(" Initializing Google OAuth Middleware...");
    logger.debug(" Config Received in Middleware:");

    if (!config.google?.enabled) {
      logger.warn(" Google OAuth is NOT enabled, skipping middleware...");
      return next(); // Skip if Google OAuth is not enabled
    }

    const authHeader = req.headers["authorization"];
    if (!authHeader) {
      logger.warn(" Unauthorized access attempt (Google OAuth missing)");
      return res.status(401).json({ error: "Unauthorized" });
    }

    const token = authHeader.split(" ")[1];
    logger.info(" Google OAuth Authorization Header Found!");

    if (!config.google.secret) {
      logger.error(" Google OAuth secret is not configured!");
      return res.status(500).json({ error: "Google OAuth secret is missing" });
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    jwt.verify(token, config.google.secret as jwt.Secret, (err, decoded: any) => {
      if (err) {
        logger.warn(" Invalid or Expired Google OAuth Token!", {
          error: err.message,
        });
        return res.status(403).json({ error: "Token is invalid or expired" });
      }

      const user = decoded as JWTPayload;

      // Check if the token type is 'access'
      if (user.type !== "access") {
        logger.warn(
          " Invalid Google OAuth token type: Only 'access' tokens are allowed!"
        );
        return res.status(403).json({ error: "Invalid token type" });
      }

      logger.info(" Google OAuth Verified Successfully!");
      req.user = user;
      next();
    });
  };
};
