const jwt = require("jsonwebtoken");
const createLogger = require("../lib/wintson.logger");
const apiResponse = require("../utils/api-response");


module.exports = (router, config) => {
  const logger = createLogger(config);

  router.get("/me", async (req, res) => {
    try {
      logger.info(" Checking authentication method...");

      // JWT Authentication Check
      if (config.jwt?.enabled) {
        const authHeader = req.headers["authorization"];
        if (authHeader) {
          const token = authHeader.split(" ")[1];
          logger.info(" JWT Token found, verifying...");

          return jwt.verify(token, config.jwt.secret, async (err, user) => {
            if (err) {
              logger.warn(" JWT verification failed", { error: err.message });
              return res
                .status(403)
                .json(apiResponse(403, "Token is Invalid or Expired", false));
            }

            logger.info(" JWT verified successfully");
            const userInfo = await config.user_service.load_user(user.username);
            if (!userInfo) {
              return res.status(404).json(apiResponse(404, "User not found", false));
            }

            return res.json(apiResponse(200, "User Details", true, [userInfo]));
          });
        }
      }

      // Session Authentication Check
      if (config.session?.enabled && req.session?.user) {
        logger.info(" Session user found, fetching details...");
        const userInfo = await config.user_service.load_user(
          req.session.user.username
        );
        if (!userInfo) {
          return res.status(404).json(apiResponse(404,"User not found", false));
        }
        return res.json(200, "User Found", true, [userInfo]);
      }

      //  Google OAuth Authentication Check
      if (config.google?.enabled) {
        const authHeader = req.headers["authorization"];
        if (authHeader) {
          const token = authHeader.split(" ")[1];
          logger.info(" Google OAuth Token found, verifying...");

          return jwt.verify(token, config.google.secret, async (err, user) => {
            if (err) {
              logger.warn(" Google OAuth verification failed", {
                error: err.message,
              });
              return res
                .status(403)
                .json(apiResponse(403, "Token is invalid or expired", false));
            }

            logger.info(" Google OAuth token verified successfully");
            const userInfo = await config.user_service.load_user(user.username);
            if (!userInfo) {
              return res.status(404).json(apiResponse(404, "User not found", false));
            }

            return res.json(apiResponse(200, "User Found", true, [userInfo]));
          });
        }
      }

      logger.warn(" No authentication method found in the request");
      return res.status(401).json(apiResponse(401, "Unauthorized", false));
    } catch (error) {
      logger.error(" Error in /me route", { error: error.message });
      return res.status(500).json(apiResponse(500, "Internal server error", false));
    }
  });
};
