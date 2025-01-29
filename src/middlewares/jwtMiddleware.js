import jwt from "jsonwebtoken";
import logger from "../lib/wintson.logger";

export function jwtMiddleware(config) {
    return function (req, res, next) {
        if (!config.jwt?.enabled) return next(); // Skip if JWT is not enabled

        const authHeader = req.headers["authorization"];
        if (!authHeader) {
            logger.warn("Unauthorized access attempt (JWT missing)");
            return res.status(401).json({ error: "Unauthorized" });
        }

        const token = authHeader.split(" ")[1];

        jwt.verify(token, config.jwt.secret || "jwt_secret@auth", (err, user) => {
            if (err) {
                logger.warn("Invalid or expired token", { error: err.message });
                return res.status(403).json({ error: "Token is invalid or expired" });
            }

            logger.info("JWT verified successfully");
            req.user = user;
            next();
        });
    };
}
