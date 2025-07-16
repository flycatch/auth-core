"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const passport_1 = __importDefault(require("passport"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const express_1 = __importDefault(require("express"));
const wintson_logger_1 = __importDefault(require("../lib/wintson.logger"));
exports.default = (router, config) => {
    router.use(express_1.default.json());
    router.get("/auth/google/login", passport_1.default.authenticate("google", { scope: ["profile", "email"] }));
    router.get("/auth/google/callback", passport_1.default.authenticate("google", { session: false }), async (req, res) => {
        try {
            wintson_logger_1.default.info("Handling Google OAuth callback");
            // Create a JWT token after successful login
            if (!req.user) {
                wintson_logger_1.default.error("User object is missing in request");
                return res.status(401).json({ error: "User not authenticated" });
            }
            const payload = {
                id: req.user.id,
                username: req.user.username,
            };
            if (!config.google || !config.google.secret) {
                wintson_logger_1.default.error("Google config or secret is missing");
                return res.status(500).json({ error: "Google configuration error" });
            }
            const token = jsonwebtoken_1.default.sign(payload, config.google.secret, {
                expiresIn: "8h",
            });
            // Send the token in the response
            res.json({
                message: "Google OAuth successful",
                token,
            });
            wintson_logger_1.default.info("User successfully logged in with Google OAuth");
        }
        catch (err) {
            wintson_logger_1.default.error("Error during Google OAuth callback", {
                error: err.message,
                stack: err.stack,
            });
            res.status(500).json({ error: "Internal server error" });
        }
    });
};
