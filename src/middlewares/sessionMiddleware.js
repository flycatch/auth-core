import logger from "../lib/wintson.logger";

export function sessionMiddleware(config) {
    return function (req, res, next) {
        if (!config.session?.enabled) return next(); // Skip if session is not enabled

        if (req.session && req.session.user) {
            logger.info("Session verified successfully");
            req.user = req.session.user;
            return next();
        }

        logger.warn("Unauthorized access attempt (Session missing)");
        return res.status(401).json({ error: "Unauthorized" });
    };
}
