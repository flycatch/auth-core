const jwt = require("jsonwebtoken");
const express = require("express");
const createLogger = require("../lib/wintson.logger");
const apiResponse = require("../utils/api-response");

module.exports = (router, config) => {
  const logger = createLogger(config);

  router.use(express.json()); 
  const   prefix = config.jwt.prefix || "/auth/jwt";

  const createAccessToken = async (user) => {
    const payload = {
      id: user.id,
      username: user.username,
      type: "access",
      ...(user.grands && user.grands.length > 0 && { grands: user.grands }) // Add only if user.grands exists and is not empty
    };
    const accessToken = jwt.sign(payload, config.jwt.secret || 'jwt_secret@auth', {
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

    const refreshToken = jwt.sign(payload, config.jwt.secret || 'jwt_secret@auth', {
      expiresIn: "7d",
    });
    return refreshToken;
  };

// Login Route
router.post(`${prefix}/login`, async (req, res) => {
  const { username, password } = req.body;

  logger.info(` Login attempt...`);
  try {
    const user = await config.user_service.load_user(username);
    if (!user) {
      logger.warn(` Login failed: User not found (username: ${username})`);
      return res.status(401).json(apiResponse(401,"Invalid username or password",false));
    }

    const isValidPassword = await config.password_checker(password, user.password);
    if (!isValidPassword) {
      logger.warn(` Login failed: Incorrect password`);
      return res.status(401).json(apiResponse(401,"Invalid username or password",false));
    }

    // Create an access token
    const accessToken = await createAccessToken(user);
    let responsePayload = { accessToken };

    // Check if refresh token is enabled before generating it
    if (config.jwt?.refresh) {
      responsePayload.refreshToken = await createRefreshToken(user);
    } else {
      logger.info(" Skipping refresh token generation (refresh is disabled)");
    }

    logger.info(` Login successful!`);
    res.json(apiResponse(200,"Login Successfull", true,[responsePayload]));
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
      return res.status(500).json(apiResponse(500, "JWT refresh is not allowed", false));
    }

      const authHeader = req.headers["authorization"];
      logger.info(`Refresh token attempt received`);
      if (!authHeader) {
        logger.warn("Refresh token missing in request");
        return res.status(400).json(apiResponse(400, "Refresh token is required", false));
      }

      try {
        logger.info("JWT refreshtoken header found, verifying...");
        const refreshToken = authHeader.split(" ")[1];
        jwt.verify(refreshToken, config.jwt.secret || 'jwt_secret@auth', async (err, user) => {
          if (err) {
            logger.warn("Invalid refresh token provided", {
              error: err.message,
            });
            return res.status(403).json(apiResponse(403,"Invalid refresh token", false));
          }

          if (user.type !== "refresh") {
            logger.warn("Invalid token type for refresh");
            return res.status(403).json(apiResponse(403, "Invalid token type", false));
          }
          const accessToken = await createAccessToken(user);
          const refreshToken = await createRefreshToken(user);

          logger.info(`Access token refreshed`);
          res.json(apiResponse(201, "Access token Refreshed", true, [accessToken, refreshToken]));
        });
      } catch (error) {
        logger.error("JWT Refresh Error", { error });
        res.status(500).json(apiResponse(500, "Internal Server Error", false));
      }
    });
  }
};
