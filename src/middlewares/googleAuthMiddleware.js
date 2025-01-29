import jwt from "jsonwebtoken";
import { Request, Response, NextFunction } from "express";
import { Config } from "../index.d";
import logger from "../logger";

export function googleAuthMiddleware(config) {
    return function (req, res, next) {
        if (!config.google?.enabled) return next(); // Skip if Google OAuth is not enabled

        const authHeader = req.headers["authorization"];
        if (!authHeader) {
            logger.warn("Unauthorized access attempt (Google OAuth missing)");
            return res.status(401).json({ error: "Unauthorized" });
        }

        const token = authHeader.split(" ")[1];

        jwt.verify(token, config.google.secret, (err, user) => {
            if (err) {
                logger.warn("Invalid or expired token (Google OAuth)", { error: err.message });
                return res.status(403).json({ error: "Token is invalid or expired" });
            }

            logger.info("Google OAuth token verified successfully");
            req.user = user;
            next();
        });
    };
}
