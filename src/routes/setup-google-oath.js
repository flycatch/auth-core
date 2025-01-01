const passport = require("passport");
const jwt = require("jsonwebtoken");
const express = require("express");

const logger = require("../lib/wintson.logger");

module.exports = (router, config) => {
  router.use(express.json()); 
  router.get(
    "/auth/google/login",
    passport.authenticate("google", { scope: ["profile", "email"] })
  );

  router.get(
    "/auth/google/callback",
    passport.authenticate("google", { session: false }),
    async (req, res) => {
      try {
        logger.info("Handling Google OAuth callback");
        // Create a JWT token after successful login
        const payload = {
          id: req.user.id,
          username: req.user.username,
          // email: req.user.email,
        };
        const token = jwt.sign(payload, config.google.secret, {
          expiresIn: "8h",
        });

        // Send the token in the response
        res.json({
          message: "Google OAuth successful",
          token,
        });
        logger.info("User successfully logged in with Google OAuth");
      } catch (err) {
        logger.error("Error during Google OAuth callback", {
          error: err.message,
          stack: err.stack,
        });
        res.status(500).json({ error: "Internal server error" });
      }
    }
  );
};
