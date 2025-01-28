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

  const createAccessToken = async (user) => {
    const payload = {
      id: user.id,
      username: user.username,
      type: "access",
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
        // // Create a JWT token after successful login
        // const payload = {
        //   id: req.user.id,
        //   username: req.user.username,
        //   type: "access"
        //   // email: req.user.email,
        // };
        // const token = jwt.sign(payload, config.google.secret, {
        //   expiresIn: "8h",
        // });

        const accessToken = await createAccessToken(req.user);
        const refreshToken = await createRefreshToken(req.user);

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
