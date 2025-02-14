const logger = require("../lib/wintson.logger");

module.exports = (config) => {
    return function (req, res, next) {
        logger.info("🔄 Initializing Session Middleware...");
        logger.debug("🛠 Config Received in Middleware");

        if (!config.session?.enabled) {
            logger.warn("⚠️ Session is NOT enabled, skipping middleware...");
            return next(); // Skip if session is not enabled
        }

        if (req.session && req.session.user) {
            logger.info("✅ Session Verified Successfully!");
            req.user = req.session.user;
            return next();
        }

        logger.warn("❌ Unauthorized access attempt (Session missing)");
        return res.status(401).json({ error: "Unauthorized" });
    };
};
