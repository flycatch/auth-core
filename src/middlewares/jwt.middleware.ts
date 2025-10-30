/* eslint-disable @typescript-eslint/no-explicit-any */
import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { Config } from "../interfaces/config.interface";
import createLogger from "../lib/wintson.logger";
import { isInBlacklist } from "../utils/jwt-blacklist";

/**
 * Express middleware for validating JWT access tokens.
 *
 * This middleware verifies the JWT token in the Authorization header,
 * checks for token blacklisting, validates token type, and attaches
 * the decoded user payload to the request object.
 *
 * @param {Config} config - Application configuration containing JWT settings.
 * @returns {import("express").RequestHandler} Express middleware function.
 */
export default (config: Config) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    const logger = createLogger(config);

    if (!config.jwt) {
      logger.error("JWT configuration not found");
      return res.status(500).json({
        error: "Something went wrong",
      });
    }

    const authHeader = req.headers["authorization"];

    if (!authHeader) {
      logger.warn("JWT middleware: No authorization header provided");
      return res.status(401).json({
        error: "Unauthorized",
      });
    }

    if (!authHeader.startsWith("Bearer ")) {
      logger.warn("JWT middleware: Invalid authorization header format");
      return res.status(401).json({
        error: "Unauthorized",
      });
    }

    const token = authHeader.split(" ")[1];

    if (!token) {
      logger.warn("JWT middleware: No token provided");
      return res.status(401).json({
        error: "Unauthorized",
      });
    }

    const isBlackisted = await isInBlacklist(token)

    // Check if token is blacklisted (only if blacklisting is enabled)
    if (config.jwt.tokenBlacklist?.enabled && isBlackisted) {
      logger.warn("JWT middleware: Blacklisted token used");
      return res.status(401).json({
        error: "Unauthorized",
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
              error: "Unauthorized",
            });
          }

          if (err.name === "JsonWebTokenError") {
            return res.status(401).json({
              error: "Unauthorized",
            });
          }

          return res.status(401).json({
            error: "Unauthorized",
          });
        }

        // Ensure it's an access token
        if (decoded.type !== "access") {
          logger.warn("JWT middleware: Invalid token type provided");
          return res.status(401).json({
            error: "Unauthorized",
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
