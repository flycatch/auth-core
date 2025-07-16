import jwt from "jsonwebtoken";
import express, { Router } from "express";
import logger from "../lib/wintson.logger";
import Config from "../interfaces/config.interface";
import JWTPayload from "../interfaces/jwt.interface";

export default (router: Router, config: Config) => {
  router.use(express.json());
  if (!config.jwt) {
    throw new Error("JWT configuration with secret is required");
  }
  const prefix = config.jwt.prefix || "/auth/jwt";

  const createAccessToken = async (user: any) => {
    const payload: JWTPayload = {
      id: user.id,
      username: user.username,
      type: "access",
    };

    if (!config.jwt || !config.jwt.secret) {
      throw new Error("JWT configuration with secret is required");
    }

    const accessToken = jwt.sign(payload, config.jwt.secret, {
      expiresIn: config.jwt.expiresIn  || "8h",
    });
    return accessToken;
  };

  const createRefreshToken = async (user: any) => {
    const payload: JWTPayload = {
      id: user.id,
      username: user.username,
      type: "refresh",
    };

    if (!config.jwt || !config.jwt.secret) {
      throw new Error("JWT configuration with secret is required");
    }

    const refreshToken = jwt.sign(payload, config.jwt.secret, {
      expiresIn: config.jwt.expiresIn || "7d",
    });
    return refreshToken;
  };

  // Login Route
  router.post(`${prefix}/login`, async (req, res) => {
    const { username, password } = req.body;

    logger.info(`Login attempt for username: ${username}`);
    try {
      const user = await config.userService.loadUser(username);
      if (!user) {
        logger.warn(`Login failed: User not found (username: ${username})`);
        return res.status(401).json({ error: "Invalid username or password" });
      }

      const isValidPassword = await config.passwordChecker(
        password,
        user.password
      );
      if (!isValidPassword) {
        logger.warn(`Login failed: Incorrect password (username: ${username})`);
        return res.status(401).json({ error: "Invalid username or password" });
      }

      const accessToken = await createAccessToken(user);
      const refreshToken = await createRefreshToken(user);
      logger.info(`Login successful for username: ${username}`);
      res.json({ accessToken, refreshToken });
    } catch (error) {
      logger.error(`JWT Login Error for username: ${username}`, { error });
      res.status(500).json({ error: "Internal Server Error" });
    }
  });

  // Refresh Token Route
  if (config.jwt.refresh) {
    router.post(`${prefix}/refresh`, async (req, res) => {
      const authHeader = req.headers["authorization"];
      logger.info(`Refresh token attempt received`);
      if (!authHeader) {
        logger.warn("Refresh token missing in request");
        return res.status(400).json({ error: "Refresh token is required" });
      }

      try {
        logger.info("JWT refreshtoken header found, verifying...");
        const refreshToken = authHeader.split(" ")[1];
        jwt.verify(
          refreshToken,
          config.jwt?.secret || "secret",
          async (err, user: any) => {
            if (err) {
              logger.warn("Invalid refresh token provided", {
                error: err.message,
              });
              return res.status(403).json({ error: "Invalid refresh token" });
            }

            if (user.type !== "refresh") {
              logger.warn("Invalid token type for refresh");
              return res.status(403).json({ error: "Invalid token type" });
            }
            const accessToken = await createAccessToken(user);
            const refreshToken = await createRefreshToken(user);

            logger.info(
              `Access token refreshed for username: ${user.username}`
            );
            res.json({ accessToken, refreshToken });
          }
        );
      } catch (error) {
        logger.error("JWT Refresh Error", { error });
        res.status(500).json({ error: "Internal Server Error" });
      }
    });
  }
};
