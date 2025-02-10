const passport = require("passport");
const jwt = require("jsonwebtoken");
const express = require("express");

const createLogger = require("../lib/wintson.logger");

module.exports = (router, config) => {
  const logger = createLogger(config);

  router.use(express.json());
  router.get(
    "/auth/google/login",
    passport.authenticate("google", { scope: ["profile", "email"] })
  );

  const createAccessToken = async (user) => {
    const payload = {
      id: user.id,
      username: user.username,
      type: "access",
      ...(user.grands && user.grands.length > 0 && { grands: user.grands }) // Add only if user.grands exists and is not empty

    };

    const accessToken = jwt.sign(payload, config.jwt.secret, {
      expiresIn: config.jwt.jwt_expires || "8h",
    });
    return accessToken;
  };

  const createRefreshToken = async (user) => {
    const payload = {
      id: user.id,
      username: user.username,
      type: "refresh",
      ...(user.grands && user.grands.length > 0 && { grands: user.grands }) // Add only if user.grands exists and is not empty
    };

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
        console.log('callback fun', accessToken);
        // Send the token in the response
        res.json({
          message: "Google OAuth successful",
          accessToken: accessToken,
          refreshToken: refreshToken,
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
