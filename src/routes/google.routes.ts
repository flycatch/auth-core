/* eslint-disable @typescript-eslint/no-explicit-any */
import { Router } from "express";
import { Config } from "../interfaces/config.interface";
import passport from "passport";
import express from "express";
import apiResponse from "../utils/api-response";
import createLogger from "../lib/wintson.logger";
import { createJwtTokens } from "../utils/jwt";
import { User } from "../interfaces/user.interface";
import { createSessionPayload } from "../utils/session";

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

        if (config.jwt && config.jwt.enabled) {
          const jwtTokens = createJwtTokens(config.jwt, req.user as User);
          logger.info("User successfully logged in with Google OAuth");
          res.json(
            apiResponse(201, "Google OAuth Successful,", true, [
              { ...jwtTokens },
            ])
          );
        } else if (config.session?.enabled) {
          const payload = createSessionPayload(req.user as User);
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
