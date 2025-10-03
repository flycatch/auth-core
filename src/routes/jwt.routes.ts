/* eslint-disable @typescript-eslint/no-explicit-any */
import { Request, Response, Router } from "express";
import { Config } from "../interfaces/config.interface";
import jwt from "jsonwebtoken";
import express from "express";
import createLogger from "../lib/wintson.logger";
import apiResponse from "../utils/api-response";
import { createJwtTokens } from "../utils/jwt";
import twoFactorAuth, {
  InvalidOtpError,
  OtpExpiredError,
  TransportNotFoundError,
} from "../utils/two-factor-auth";

// Token blacklist management - only used if enabled
const tokenBlacklist = new Set<string>();

// Helper functions for blacklist management
export const blacklistToken = (token: string): void => {
  tokenBlacklist.add(token);
};

export const isTokenBlacklisted = (token: string): boolean => {
  return tokenBlacklist.has(token);
};

export const clearBlacklist = (): void => {
  tokenBlacklist.clear();
};

// Custom blacklist storage interface
interface BlacklistStorage {
  add: (token: string, expiresAt?: Date) => Promise<void> | void;
  has: (token: string) => Promise<boolean> | boolean;
  remove: (token: string) => Promise<void> | void;
  clear: () => Promise<void> | void;
}

let blacklistStorage: BlacklistStorage | null = null;

export const setBlacklistStorage = (storage: BlacklistStorage): void => {
  blacklistStorage = storage;
};

// Universal blacklist functions that work with custom or default storage
const addToBlacklist = async (
  token: string,
  expiresAt?: Date
): Promise<void> => {
  if (blacklistStorage) {
    await blacklistStorage.add(token, expiresAt);
  } else {
    blacklistToken(token);
  }
};

const isInBlacklist = async (token: string): Promise<boolean> => {
  if (blacklistStorage) {
    return await blacklistStorage.has(token);
  }
  return isTokenBlacklisted(token);
};

export default (router: Router, config: Config) => {
  if (!config.jwt) {
    throw new Error("JWT not configured");
  }

  const logger = createLogger(config);
  router.use(express.json());
  const prefix = config.jwt.prefix || "/auth/jwt";
  const isBlacklistEnabled = config.jwt.tokenBlacklist?.enabled ?? false;

  const { initiate2fa, verifyOtp } = twoFactorAuth(config.twoFA);

  // Login Route
  if (!config.twoFA?.enabled) {
    router.post(`${prefix}/login`, async (req: Request, res: Response) => {
      if (!config.jwt) {
        throw new Error("JWT not configured");
      }

      const { username, password } = req.body;
      logger.info(`Login attempt for user: ${username}`);

      // Validate input
      if (!username || !password) {
        logger.warn("Login failed: Missing username or password");
        return res
          .status(400)
          .json(apiResponse(400, "Username and password are required", false));
      }

      try {
        const user = await config.userService.loadUser(username);
        if (!user) {
          logger.warn(`Login failed: User not found (username: ${username})`);
          return res.status(401).json(apiResponse(401, "Login Failed", false));
        }

        const isValidPassword = await config.passwordChecker(
          password,
          user.password
        );

        if (!isValidPassword) {
          logger.warn(`Login failed: Incorrect password for user: ${username}`);
          return res.status(401).json(apiResponse(401, "Login Failed", false));
        }

        // Create jwt tokens
        const jwtTokens = createJwtTokens(config.jwt, user);
        logger.info(`Login successful for user: ${username}`);

        res.json(apiResponse(200, "Login successful", true, [jwtTokens]));
      } catch (error) {
        logger.error(`JWT Login Error for username: ${username}`, { error });
        res.status(500).json(apiResponse(500, "Internal Server Error", false));
      }
    });
  } else {
    router.post(`${prefix}/login`, async (req: Request, res: Response) => {
      try {
        if (!config.twoFA || !config.twoFA.enabled) {
          throw new Error("Two Factor Authentication is not enabled");
        }

        const { username } = req.body;
        if (!username) {
          return res
            .status(400)
            .json({ message: "Email required on request payload" });
        }

        const user = await config.userService.loadUser(username);
        if (!user) {
          logger.warn(`Invalid username`);
          return res.status(401).json({ message: "Login Failed" });
        }

        if (!user.is2faEnabled) {
          logger.warn("Two Factor Authentication is not enabled for the user");
          return res.status(403).json({
            error: "Two Factor Authentication is not enabled for the user",
          });
        }

        await initiate2fa(user);
        logger.info(`OTP Generated and transported succesfully`);
        res.status(200).json({
          message: "Send One Time Password for Two Factor Authentication",
        });
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      } catch (error: any) {
        if (error instanceof TransportNotFoundError) {
          logger.warn(error.message);
          return res
            .status(500)
            .json({ error: "OTP generated, but No Transport Available" });
        }
        logger.error(`Two Factor Auth initalization Failed: ${error.message}`);
        res.status(500).json({
          error: "Two Factor Auth initalization Failed",
        });
      }
    });

    router.post(`${prefix}/verify`, async (req: Request, res: Response) => {
      const { otp, email } = req.body;
      if (!otp || !email) {
        return res.status(400).json({
          error: "Both 'otp' and 'email' are required in the request payload.",
        });
      }

      try {
        const user = await config.userService.loadUser(email);
        if (!user) {
          logger.warn("Invalid User")
          return res.status(401).json({ error: "Login Failed" });
        }

        const isValid = await verifyOtp(user, otp);
        if (!isValid) {
          logger.warn("Invalid OTP")
          res.status(401).json({ error: "Login Failed" });
        }

        logger.info("OTP Verified Successfully");

        if (!config.jwt) {
          throw Error("Jwt Configuration not found at verification");
        }

        const tokens = createJwtTokens(config.jwt, user);

        logger.info(`JWT Login Succesful`);
        res.json(
          apiResponse(201, "Two Factor Oath Successful", true, [tokens])
        );

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      } catch (error: any) {
        if (error instanceof OtpExpiredError || InvalidOtpError) {
          logger.warn(error.message);
          return res.status(401).json({ error: error.message });
        }
        logger.error(error.message);
        res.status(500).json({ error: error.message });
      }
    });
  }

  // Refresh Token Route
  if (config.jwt.refresh) {
    router.post(`${prefix}/refresh`, async (req, res) => {
      // Ensure JWT refresh is enabled in the config
      if (!config.jwt?.refresh) {
        logger.error("JWT refresh is disabled in the configuration.");
        return res
          .status(500)
          .json(apiResponse(500, "JWT refresh is not allowed", false));
      }

      const authHeader = req.headers["authorization"];
      logger.info("Refresh token attempt received");

      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        logger.warn("Refresh token missing or invalid format in request");
        return res
          .status(400)
          .json(apiResponse(400, "Valid refresh token is required", false));
      }

      try {
        logger.info("JWT refresh token header found, verifying...");
        const refreshToken = authHeader.split(" ")[1];

        // Check if token is blacklisted (only if blacklisting is enabled)
        if (isBlacklistEnabled && (await isInBlacklist(refreshToken))) {
          logger.warn("Blacklisted refresh token provided");
          return res
            .status(403)
            .json(apiResponse(403, "Token has been revoked", false));
        }

        jwt.verify(
          refreshToken,
          config.jwt.secret || "jwt_secret@auth",
          async (err: any, decoded: any) => {
            if (err) {
              logger.warn("Invalid refresh token provided", {
                error: err.message,
              });
              return res
                .status(403)
                .json(apiResponse(403, "Invalid refresh token", false));
            }

            if (decoded.type !== "refresh") {
              logger.warn("Invalid token type for refresh");
              return res
                .status(403)
                .json(apiResponse(403, "Invalid token type", false));
            }

            if (!config.jwt) {
              throw new Error("JWT not configured");
            }

            // Create new tokens
            const jwtTokens = createJwtTokens(config.jwt, decoded);

            // Optionally blacklist the old refresh token (only if blacklisting enabled and configured)
            if (isBlacklistEnabled && config.jwt.revokeOnRefresh) {
              try {
                const tokenExp = decoded.exp
                  ? new Date(decoded.exp * 1000)
                  : undefined;
                await addToBlacklist(refreshToken, tokenExp);
                logger.info(
                  `Old refresh token blacklisted for user: ${decoded.username}`
                );
              } catch (error) {
                logger.warn("Failed to blacklist old refresh token", { error });
              }
            }

            logger.info(`Access token refreshed for user: ${decoded.username}`);
            res.json(
              apiResponse(200, "Access token refreshed", true, [jwtTokens])
            );
          }
        );
      } catch (error) {
        logger.error("JWT Refresh Error", { error });
        res.status(500).json(apiResponse(500, "Internal Server Error", false));
      }
    });
  }

  // Logout Route - Simple or with blacklisting based on configuration
  router.post(`${prefix}/logout`, async (req, res) => {
    const authHeader = req.headers["authorization"];
    logger.info("Logout attempt received");

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      // If no token provided, just return success (client-side logout)
      logger.info("Logout completed (client-side only - no token provided)");
      return res.json(apiResponse(200, "Logout successful", true));
    }

    try {
      const token = authHeader.split(" ")[1];

      if (isBlacklistEnabled) {
        // Full logout with token blacklisting
        jwt.verify(
          token,
          config.jwt?.secret || "jwt_secret@auth",
          async (err: any, decoded: any) => {
            if (err) {
              // Even if token is invalid, logout is successful from client perspective
              logger.info("Logout completed (invalid token - client cleanup)");
              return res.json(apiResponse(200, "Logout successful", true));
            }

            try {
              // Add token to blacklist with expiration
              const tokenExp = decoded.exp
                ? new Date(decoded.exp * 1000)
                : undefined;
              await addToBlacklist(token, tokenExp);

              logger.info(
                `Logout successful for user: ${
                  decoded?.username || "unknown"
                } - token blacklisted`
              );
              res.json(apiResponse(200, "Logout successful", true));
            } catch (error) {
              logger.error("Error during logout blacklisting", { error });
              // Even if blacklisting fails, logout from client perspective is successful
              res.json(apiResponse(200, "Logout successful", true));
            }
          }
        );
      } else {
        // Simple logout without blacklisting - just log and return success
        // Token validation is optional here since it's just for logging
        try {
          jwt.verify(
            token,
            config.jwt?.secret || "jwt_secret@auth",
            (err: any, decoded: any) => {
              if (!err && decoded) {
                logger.info(
                  `Logout successful for user: ${
                    decoded?.username || "unknown"
                  } - client-side only`
                );
              } else {
                logger.info("Logout completed - client-side cleanup");
              }
            }
          );
          // eslint-disable-next-line @typescript-eslint/no-unused-vars
        } catch (error) {
          logger.info("Logout completed - client-side cleanup");
        }

        res.json(apiResponse(200, "Logout successful", true));
      }
    } catch (error) {
      logger.error("JWT Logout Error", { error });
      // Even on error, logout should be successful from client perspective
      res.json(apiResponse(200, "Logout successful", true));
    }
  });

  // Logout All Sessions Route (only available with blacklisting enabled)
  if (config.jwt.refresh && isBlacklistEnabled) {
    router.post(`${prefix}/logout-all`, async (req, res) => {
      const authHeader = req.headers["authorization"];
      logger.info("Logout all sessions attempt received");

      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        logger.warn("Logout all failed: No token provided");
        return res
          .status(400)
          .json(apiResponse(400, "Token is required for logout-all", false));
      }

      try {
        const token = authHeader.split(" ")[1];

        jwt.verify(
          token,
          config.jwt?.secret || "jwt_secret@auth",
          async (err: any, decoded: any) => {
            if (err) {
              logger.warn("Logout all failed: Invalid token", {
                error: err.message,
              });
              return res
                .status(401)
                .json(apiResponse(401, "Invalid token", false));
            }

            try {
              // Blacklist current token
              const tokenExp = decoded.exp
                ? new Date(decoded.exp * 1000)
                : undefined;
              await addToBlacklist(token, tokenExp);

              // Call custom logout all handler if provided
              if (config.jwt && config.jwt.tokenBlacklist?.onLogoutAll) {
                await config.jwt.tokenBlacklist.onLogoutAll(
                  decoded.id || decoded.username
                );
              }

              logger.info(
                `Logout all successful for user: ${
                  decoded?.username || "unknown"
                }`
              );
              res.json(
                apiResponse(200, "All sessions logged out successfully", true)
              );
            } catch (error) {
              logger.error("JWT Logout All Error", { error });
              res
                .status(500)
                .json(apiResponse(500, "Internal Server Error", false));
            }
          }
        );
      } catch (error) {
        logger.error("JWT Logout All Error", { error });
        res.status(500).json(apiResponse(500, "Internal Server Error", false));
      }
    });
  }

  // Initialize custom blacklist storage if provided
  if (isBlacklistEnabled && config.jwt.tokenBlacklist?.storageService) {
    setBlacklistStorage(config.jwt.tokenBlacklist.storageService);
    logger.info("Custom blacklist storage initialized");
  }
};
