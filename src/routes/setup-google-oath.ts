import passport from "passport";
import jwt from "jsonwebtoken";
import express, { Request, Response, Router } from "express";
import logger from "../lib/wintson.logger";
import Config from "../interfaces/config.interface";

export default (router: Router, config: Config) => {
  router.use(express.json());
  router.get(
    "/auth/google/login",
    passport.authenticate("google", { scope: ["profile", "email"] })
  );

  router.get(
    "/auth/google/callback",
    passport.authenticate("google", { session: false }),
    async (req: Request, res: Response) => {
      try {
        logger.info("Handling Google OAuth callback");
        // Create a JWT token after successful login
        if (!req.user) {
          logger.error("User object is missing in request");
          return res.status(401).json({ error: "User not authenticated" });
        }
        const payload = {
          id: req.user.id,
          username: req.user.username,
        };
        if (!config.google || !config.google.secret) {
          logger.error("Google config or secret is missing");
          return res.status(500).json({ error: "Google configuration error" });
        }
        const token = jwt.sign(payload, config.google.secret, {
          expiresIn: "8h",
        });

        // Send the token in the response
        res.json({
          message: "Google OAuth successful",
          token,
        });
        logger.info("User successfully logged in with Google OAuth");
      } catch (err: any) {
        logger.error("Error during Google OAuth callback", {
          error: err.message,
          stack: err.stack,
        });
        res.status(500).json({ error: "Internal server error" });
      }
    }
  );
};
