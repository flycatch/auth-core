import Config from "../interfaces/config.interface";
import jwt from "jsonwebtoken";
import logger from "../lib/wintson.logger";
import { NextFunction, Request, Response } from "express";
import JWTPayload from "../interfaces/jwt.interface";

export default (config: Config) =>
  (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];
    if (!token) {
      logger.warn("Unauthorized access attempt: Missing token");
      return res.status(401).json({ error: "Unauthorized" });
    }

    if (!config.jwt) {
      throw new Error("JWT configuration with secret is required");
    }

    jwt.verify(token, config.jwt.secret, (err, user) => {
      if (err) {
        logger.warn("Invalid or expired token", { error: err.message });
        return res.status(403).json({ error: "Token is invalid or expired" });
      }

      logger.info(
        `Token verified successfully for username: ${
          (user as JWTPayload).username
        }`
      );
      req.user = user as Express.User;
      next();
    });
  };
