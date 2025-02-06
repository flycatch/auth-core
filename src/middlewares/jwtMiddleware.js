const jwt = require("jsonwebtoken");
const logger = require("../lib/wintson.logger");

module.exports = (config) => {
  logger.info("🔄 Initializing JWT Middleware...");

  return function (req, res, next) {
    logger.info("✅ JWT Middleware Started...");

    // Check if JWT is enabled
    if (!config || !config.jwt || !config.jwt.enabled) {
      logger.info("⚠️ JWT is NOT enabled, skipping middleware...");
      return next();
    }

    const authHeader = req.headers["authorization"];

    if (!authHeader) {
      logger.warn("🚫 Unauthorized access attempt (JWT missing)");
      return res.status(401).json({ error: "Unauthorized" });
    }

    const token = authHeader.split(" ")[1];

    jwt.verify(token, config.jwt.secret || "jwt_secret@auth", (err, user) => {
      if (err) {
        logger.warn("❌ Invalid or expired token", { error: err.message });
        return res.status(403).json({ error: "Token is invalid or expired" });
      }

      logger.info("✅ JWT Verified Successfully!");
      req.user = user; 
      next();
    });
  };
};
