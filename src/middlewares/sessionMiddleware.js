const createLogger = require("../lib/wintson.logger");

module.exports = (config) => {
  return function (req, res, next) {
    const logger = createLogger(config);

    logger.info("Initializing Session Middleware...");
    logger.debug("Config Received in Middleware");

    if (!config.session?.enabled) {
      logger.warn(" Session is NOT enabled, skipping middleware...");
      return next(); // Skip if session is not enabled
    }

    if (req.session && req.session.user) {
      // Check if the token type is 'access'
      if (req.session.user.type !== "access") {
        logger.warn(" Invalid session type: Only 'access' sessions are allowed!");
        return res.status(403).json({ error: "Invalid session type" });
      }

      logger.info(" Session Verified Successfully!");
      req.user = req.session.user;
      return next();
    }

    logger.warn(" Unauthorized access attempt (Session missing)");
    return res.status(401).json({ error: "Unauthorized" });
  };
};
