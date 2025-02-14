const jwt = require("jsonwebtoken");
const logger = require("../lib/wintson.logger");

module.exports = (config) => {
    return function (req, res, next) {
        logger.info("🔄 Initializing Google OAuth Middleware...");
        logger.debug("🛠 Config Received in Middleware:");

        if (!config.google?.enabled) {
            logger.warn("⚠️ Google OAuth is NOT enabled, skipping middleware...");
            return next(); // Skip if Google OAuth is not enabled
        }

        const authHeader = req.headers["authorization"];
        if (!authHeader) {
            logger.warn("❌ Unauthorized access attempt (Google OAuth missing)");
            return res.status(401).json({ error: "Unauthorized" });
        }

        const token = authHeader.split(" ")[1];
        logger.info("🔑 Google OAuth Authorization Header Found!");

        jwt.verify(token, config.google.secret, (err, user) => {
            if (err) {
                logger.warn("⛔ Invalid or Expired Google OAuth Token!", { error: err.message });
                return res.status(403).json({ error: "Token is invalid or expired" });
            }

            logger.info("✅ Google OAuth Verified Successfully!");
            req.user = user;
            next();
        });
    };
};
