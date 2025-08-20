/* eslint-disable @typescript-eslint/no-explicit-any */
import { Router } from "express";
import { Config } from "../interfaces/config.interface";
import jwt from "jsonwebtoken";
import express from "express";
import createLogger from "../lib/wintson.logger";
import apiResponse from "../utils/api-response";
import { createJwtTokens } from "../utils/jwt";

export default (router: Router, config: Config) => {
  if (!config.jwt) {
    throw new Error("JWT not cnfigured");
  }
  const logger = createLogger(config);

  router.use(express.json());
  const prefix = config.jwt.prefix || "/auth/jwt";

  // Login Route
  router.post(`${prefix}/login`, async (req, res) => {
    if (!config.jwt) {
      throw new Error("JWT not cnfigured");
    }
    const { username, password } = req.body;

    logger.info(` Login attempt...`);
    try {
      const user = await config.userService.loadUser(username);
      if (!user) {
        logger.warn(` Login failed: User not found (username: ${username})`);
        return res
          .status(401)
          .json(apiResponse(401, "Invalid username or password", false));
      }

      const isValidPassword = await config.passwordChecker(
        password,
        user.password
      );
      if (!isValidPassword) {
        logger.warn(` Login failed: Incorrect password`);
        return res
          .status(401)
          .json(apiResponse(401, "Invalid username or password", false));
      }

      // Create jwt tokens
      const jwtTokens = createJwtTokens(config.jwt, user);

      logger.info(` Login successful!`);
      res.json(apiResponse(200, "Login Successful", true, [jwtTokens]));
    } catch (error) {
      logger.error(` JWT Login Error for username: ${username}`, { error });
      res.status(500).json(apiResponse(500, "Internal Server Error", false));
    }
  });

  // Refresh Token Route
  if (config.jwt.refresh) {
    router.post(`${prefix}/refresh`, async (req, res) => {
      // Ensure JWT refresh is enabled in the config
      if (!config.jwt?.refresh) {
        logger.error(" JWT refresh is disabled in the configuration.");
        return res
          .status(500)
          .json(apiResponse(500, "JWT refresh is not allowed", false));
      }

      const authHeader = req.headers["authorization"];
      logger.info(`Refresh token attempt received`);
      if (!authHeader) {
        logger.warn("Refresh token missing in request");
        return res
          .status(400)
          .json(apiResponse(400, "Refresh token is required", false));
      }

      try {
        logger.info("JWT refreshtoken header found, verifying...");
        const refreshToken = authHeader.split(" ")[1];
        jwt.verify(
          refreshToken,
          config.jwt.secret || "jwt_secret@auth",
          async (err: any, user: any) => {
            if (err) {
              logger.warn("Invalid refresh token provided", {
                error: err.message,
              });
              return res
                .status(403)
                .json(apiResponse(403, "Invalid refresh token", false));
            }

            if (user.type !== "refresh") {
              logger.warn("Invalid token type for refresh");
              return res
                .status(403)
                .json(apiResponse(403, "Invalid token type", false));
            }

            if (!config.jwt) {
              throw new Error("JWT not cnfigured");
            }
            const jwtTokens = createJwtTokens(config.jwt, user);

            logger.info(`Access token refreshed`);
            res.json(
              apiResponse(201, "Access token Refreshed", true, [jwtTokens])
            );
          }
        );
      } catch (error) {
        logger.error("JWT Refresh Error", { error });
        res.status(500).json(apiResponse(500, "Internal Server Error", false));
      }
    });
  }
};
