/* eslint-disable @typescript-eslint/no-explicit-any */
import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { Config } from "../interfaces/config.interface";
import createLogger from "../lib/wintson.logger";
import { isTokenBlacklisted } from "../routes/jwt.routes";

// Extend Request interface to include user

export default (config: Config) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const logger = createLogger(config);

    if (!config.jwt) {
      logger.error("JWT configuration not found");
      return res.status(500).json({
        error: "JWT configuration not found",
      });
    }

    const authHeader = req.headers["authorization"];

    if (!authHeader) {
      logger.warn("JWT middleware: No authorization header provided");
      return res.status(401).json({
        error: "Access token is required",
      });
    }

    if (!authHeader.startsWith("Bearer ")) {
      logger.warn("JWT middleware: Invalid authorization header format");
      return res.status(401).json({
        error: "Invalid token format. Use Bearer <token>",
      });
    }

    const token = authHeader.split(" ")[1];

    if (!token) {
      logger.warn("JWT middleware: No token provided");
      return res.status(401).json({
        error: "Access token is required",
      });
    }

    // Check if token is blacklisted (only if blacklisting is enabled)
    if (config.jwt.tokenBlacklist?.enabled && isTokenBlacklisted(token)) {
      logger.warn("JWT middleware: Blacklisted token used");
      return res.status(403).json({
        error: "Token has been revoked",
      });
    }

    try {
      const secret = config.jwt.secret || "jwt_secret@auth";

      jwt.verify(token, secret, (err: any, decoded: any) => {
        if (err) {
          logger.warn("JWT middleware: Token verification failed", {
            error: err.message,
          });

          if (err.name === "TokenExpiredError") {
            return res.status(401).json({
              error: "Token has expired",
            });
          }

          if (err.name === "JsonWebTokenError") {
            return res.status(401).json({
              error: "Invalid token",
            });
          }

          return res.status(401).json({
            error: "Token verification failed",
          });
        }

        // Ensure it's an access token
        if (decoded.type !== "access") {
          logger.warn("JWT middleware: Invalid token type provided");
          return res.status(403).json({
            error: "Invalid token type",
          });
        }

        // Add user to request object
        req.user = {
          id: decoded.id,
          username: decoded.username,
          grants: decoded.grants || [],
          tokenType: decoded.type,
        };

        logger.info(
          `JWT middleware: Access granted to user: ${decoded.username}`
        );
        next();
      });
    } catch (error) {
      logger.error("JWT middleware: Unexpected error", { error });
      return res.status(500).json({
        error: "Internal server error",
      });
    }
  };
};
