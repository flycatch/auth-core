/* eslint-disable @typescript-eslint/no-explicit-any */
import { Router } from "express";
import { Config } from "../interfaces/config.interface";
import passport from "passport";
import jwt from "jsonwebtoken";
import express from "express";
import apiResponse from "../utils/api-response";
import createLogger from "../lib/wintson.logger";

export default (router: Router, config: Config) => {
  const logger = createLogger(config);

  if (!config.google) {
    throw new Error("Google OAuth Not configured");
  }

  router.use(express.json());
  router.get(
    `${config.google.prefix ? config.google.prefix : "/auth/google"}/login`,
    passport.authenticate("google", { scope: ["profile", "email"] })
  );

  const createAccessToken = async (user: any) => {
    const payload = {
      id: user.id,
      username: user.username,
      type: "access",
      ...(user.grands && user.grands.length > 0 && { grands: user.grands }), // Add only if user.grands exists and is not empty
    };

    if (!config.jwt || !config.jwt.secret) {
      throw new Error("JWT configuration is missing or incomplete.");
    }

    const accessToken = jwt.sign(payload, config.jwt.secret, {
      expiresIn: config.jwt.expiresIn || "8h",
    });
    return accessToken;
  };

  const createRefreshToken = async (user: any) => {
    const payload = {
      id: user.id,
      username: user.username,
      type: "refresh",
      ...(user.grands && user.grands.length > 0 && { grands: user.grands }), // Add only if user.grands exists and is not empty
    };

    if (!config.jwt || !config.jwt.secret) {
      throw new Error("JWT configuration is missing or incomplete.");
    }
    const refreshToken = jwt.sign(payload, config.jwt.secret, {
      expiresIn: "7d",
    });
    return refreshToken;
  };

  const createSessionPayload = (user: any) => {
    return {
      id: user.id,
      username: user.username,
      type: "access",
      ...(user.grands && user.grands.length > 0 && { grands: user.grands }), // Add only if user.grands exists and is not empty
    };
  };

  router.get(
    `${config.google.prefix ? config.google.prefix : "/auth/google"}/callback`,
    passport.authenticate("google", { session: false }),
    async (req, res) => {
      try {
        logger.info("Handling Google OAuth callback");

        if (!req.user) {
          logger.error("User Data Missed on callback");
          return res.status(500).json({ error: "Something went wrong" });
        }

        if (config.jwt?.enabled) {
          const accessToken = await createAccessToken(req.user);
          const refreshToken = await createRefreshToken(req.user);
          logger.info("User successfully logged in with Google OAuth");
          res.json(
            apiResponse(201, "Google OAuth Successful,", true, [
              accessToken,
              refreshToken,
            ])
          );
        } else if (config.session?.enabled) {
          const payload = createSessionPayload(req.user);
          // Store user details in session
          req.session.user = payload;

          logger.info(`session Login successful `);
          return res.json(
            apiResponse(201, "Login Successful", true, [payload])
          );
        } else {
          logger.error(
            "Either Jwt or Session should be configured to get tokens from google OAuth"
          );
          res.status(500).json({
            error: "Either JWT or Session auth configured to use google OAuth",
          });
        }
      } catch (err: any) {
        logger.error("Error during Google OAuth callback", {
          error: err.message,
          stack: err.stack,
        });
        res.status(500).json(apiResponse(500, "Internal server error", false));
      }
    }
  );
};
