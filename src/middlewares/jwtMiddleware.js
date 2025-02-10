const jwt = require("jsonwebtoken");
const createLogger = require("../lib/wintson.logger");

module.exports = (config) => {
  logger.info(" Initializing JWT Middleware...");

  return function (req, res, next) {

    const logger = createLogger(config);

    logger.info(" JWT Middleware Started...");

    // Check if JWT is enabled
    if (!config || !config.jwt || !config.jwt.enabled) {
      logger.info(" JWT is NOT enabled, skipping middleware...");
      return next();
    }

    const authHeader = req.headers["authorization"];
    if (!authHeader) {
      logger.warn(" Unauthorized access attempt (JWT missing)");
      return res.status(401).json({ error: "Unauthorized" });
    }

    const token = authHeader.split(" ")[1];

    jwt.verify(token, config.jwt.secret || "jwt_secret@auth", (err, user) => {
      if (err) {
        logger.warn(" Invalid or expired token", { error: err.message });
        return res.status(403).json({ error: "Token is invalid or expired" });
      }

      // Check if the token type is 'access'
      if (user.type !== "access") {
        logger.warn(" Invalid token type: Only 'access' tokens are allowed for authentication!");
        return res.status(403).json({ error: "Invalid token type" });
      }

      logger.info(" JWT Verified Successfully!");
      req.user = user;
      next();
    });
  };
};
