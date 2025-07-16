"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const wintson_logger_1 = __importDefault(require("../lib/wintson.logger"));
const express_1 = __importDefault(require("express"));
exports.default = (router, config) => {
    var _a;
    router.use(express_1.default.json());
    const prefix = ((_a = config.session) === null || _a === void 0 ? void 0 : _a.prefix) || "/auth/session";
    //Login Route
    router.post(`${prefix}/login`, async (req, res) => {
        const { username, password } = req.body;
        wintson_logger_1.default.info(` session login attempt for username: ${username}`);
        try {
            const user = await config.userService.loadUser(username);
            if (!user) {
                wintson_logger_1.default.warn(`Login failed: User not found (username ${username})`);
                res.status(401).json({ error: "Invalid username or password" });
            }
            const validPassword = await config.passwordChecker(password, user.password);
            if (!validPassword) {
                wintson_logger_1.default.warn(`Login failed: invalid password`);
                res.status(401).json({ error: "Invalid username or password" });
            }
            // Store user details in session
            req.session.user = { username: user.username };
            wintson_logger_1.default.info(`session Login successfull for username: ${username}`);
            res.json({ message: "Login Successfull" });
        }
        catch (error) {
            wintson_logger_1.default.error(`session Login error for username ${username} `, error);
            res.status(500).json({ error: "Internal server error" });
        }
    });
};
