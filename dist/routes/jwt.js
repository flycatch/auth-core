"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const express_1 = __importDefault(require("express"));
const wintson_logger_1 = __importDefault(require("../lib/wintson.logger"));
exports.default = (router, config) => {
    router.use(express_1.default.json());
    if (!config.jwt) {
        throw new Error("JWT configuration with secret is required");
    }
    const prefix = config.jwt.prefix || "/auth/jwt";
    const createAccessToken = async (user) => {
        const payload = {
            id: user.id,
            username: user.username,
            type: "access",
        };
        if (!config.jwt || !config.jwt.secret) {
            throw new Error("JWT configuration with secret is required");
        }
        const accessToken = jsonwebtoken_1.default.sign(payload, config.jwt.secret, {
            expiresIn: config.jwt.expiresIn || "8h",
        });
        return accessToken;
    };
    const createRefreshToken = async (user) => {
        const payload = {
            id: user.id,
            username: user.username,
            type: "refresh",
        };
        if (!config.jwt || !config.jwt.secret) {
            throw new Error("JWT configuration with secret is required");
        }
        const refreshToken = jsonwebtoken_1.default.sign(payload, config.jwt.secret, {
            expiresIn: config.jwt.expiresIn || "7d",
        });
        return refreshToken;
    };
    // Login Route
    router.post(`${prefix}/login`, async (req, res) => {
        const { username, password } = req.body;
        wintson_logger_1.default.info(`Login attempt for username: ${username}`);
        try {
            const user = await config.userService.loadUser(username);
            if (!user) {
                wintson_logger_1.default.warn(`Login failed: User not found (username: ${username})`);
                return res.status(401).json({ error: "Invalid username or password" });
            }
            const isValidPassword = await config.passwordChecker(password, user.password);
            if (!isValidPassword) {
                wintson_logger_1.default.warn(`Login failed: Incorrect password (username: ${username})`);
                return res.status(401).json({ error: "Invalid username or password" });
            }
            const accessToken = await createAccessToken(user);
            const refreshToken = await createRefreshToken(user);
            wintson_logger_1.default.info(`Login successful for username: ${username}`);
            res.json({ accessToken, refreshToken });
        }
        catch (error) {
            wintson_logger_1.default.error(`JWT Login Error for username: ${username}`, { error });
            res.status(500).json({ error: "Internal Server Error" });
        }
    });
    // Refresh Token Route
    if (config.jwt.refresh) {
        router.post(`${prefix}/refresh`, async (req, res) => {
            var _a;
            const authHeader = req.headers["authorization"];
            wintson_logger_1.default.info(`Refresh token attempt received`);
            if (!authHeader) {
                wintson_logger_1.default.warn("Refresh token missing in request");
                return res.status(400).json({ error: "Refresh token is required" });
            }
            try {
                wintson_logger_1.default.info("JWT refreshtoken header found, verifying...");
                const refreshToken = authHeader.split(" ")[1];
                jsonwebtoken_1.default.verify(refreshToken, ((_a = config.jwt) === null || _a === void 0 ? void 0 : _a.secret) || "secret", async (err, user) => {
                    if (err) {
                        wintson_logger_1.default.warn("Invalid refresh token provided", {
                            error: err.message,
                        });
                        return res.status(403).json({ error: "Invalid refresh token" });
                    }
                    if (user.type !== "refresh") {
                        wintson_logger_1.default.warn("Invalid token type for refresh");
                        return res.status(403).json({ error: "Invalid token type" });
                    }
                    const accessToken = await createAccessToken(user);
                    const refreshToken = await createRefreshToken(user);
                    wintson_logger_1.default.info(`Access token refreshed for username: ${user.username}`);
                    res.json({ accessToken, refreshToken });
                });
            }
            catch (error) {
                wintson_logger_1.default.error("JWT Refresh Error", { error });
                res.status(500).json({ error: "Internal Server Error" });
            }
        });
    }
};
