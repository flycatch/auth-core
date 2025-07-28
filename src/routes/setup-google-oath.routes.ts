import { Router } from "express";
import { Config } from "../interfaces/config.interface";
import passport from "passport";
import jwt from "jsonwebtoken";
import express from "express";
import apiResponse from "../utils/api-response";
import createLogger from "../lib/wintson.logger";

export default (router: Router, config: Config) => {
  const logger = createLogger(config);

  router.use(express.json());
  router.get(
    "/auth/google/login",
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

  router.get(
    "/auth/google/callback",
    passport.authenticate("google", { session: false }),
    async (req, res) => {
      try {
        logger.info("Handling Google OAuth callback");

        const accessToken = await createAccessToken(req.user);
        const refreshToken = await createRefreshToken(req.user);
        res.json(
          apiResponse(201, "Google Oath Successfull", true, [
            accessToken,
            refreshToken,
          ])
        );
        logger.info("User successfully logged in with Google OAuth");
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
