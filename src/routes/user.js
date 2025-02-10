const jwt = require("jsonwebtoken");
const createLogger = require("../lib/wintson.logger");

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
                .json({ error: "Token is invalid or expired" });
            }

            logger.info(" JWT verified successfully");
            const userInfo = await config.user_service.load_user(user.username);
            if (!userInfo) {
              return res.status(404).json({ error: "User not found" });
            }

            return res.json({ userInfo });
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
          return res.status(404).json({ error: "User not found" });
        }
        return res.json({ userInfo });
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
                .json({ error: "Token is invalid or expired" });
            }

            logger.info(" Google OAuth token verified successfully");
            const userInfo = await config.user_service.load_user(user.username);
            if (!userInfo) {
              return res.status(404).json({ error: "User not found" });
            }

            return res.json({ userInfo });
          });
        }
      }

      logger.warn(" No authentication method found in the request");
      return res.status(401).json({ error: "Unauthorized" });
    } catch (error) {
      logger.error(" Error in /me route", { error: error.message });
      return res.status(500).json({ error: "Internal server error" });
    }
  });
};
