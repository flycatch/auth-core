import { NextFunction, Request, Response, Router } from "express";
import { Config } from "./interfaces/config.interface";
import express from "express";
import createLogger from "./lib/wintson.logger";
import jwtRoutes from "./routes/jwt.routes";
import sessionRoutes from "./routes/session.routes";
import setupSession from "./config/session.config";
import oauth2Routes from "./routes/oauth2.routes";
import jwtMiddleware from "./middlewares/jwt.middleware";
import sessionMiddleware from "./middlewares/session.middleware";
import passport from "passport";
import oauth2Config from "./config/oauth2.config";

// Configuration storage
let configurations: Config = {} as Config;

// Function to initialize configurations and set up routes
function config(config: Config): Router {
  const jwtEnabled = config.jwt?.enabled ?? false;
  const sessionEnabled = config.session?.enabled ?? false;
  if (jwtEnabled && sessionEnabled) {
    throw new Error(
      "Cannot enable both JWT and Session authentication simultaneously."
    );
  }
  if (!jwtEnabled && !sessionEnabled) {
    throw new Error(
      "At least one of JWT or Session authentication must be enabled."
    );
  }

  // Validate required settings (expand as needed for other configs like OAuth, 2FA)
  if (jwtEnabled && !config.jwt?.secret) {
    throw new Error("JWT secret is required when JWT is enabled.");
  }
  if (sessionEnabled && !config.session?.secret) {
    throw new Error("Session secret is required when Session is enabled.");
  }
  if (
    config.twoFA?.enabled &&
    (!config.twoFA.storeOtp || !config.twoFA.getStoredOtp)
  ) {
    throw new Error("User service is required for 2FA to handle OTP storage.");
  }

  if (config.oauth2?.enabled) {
    if (!config.oauth2.successRedirect) {
      throw new Error(
        "OAuth2 successRedirect is required when OAuth2 is enabled"
      );
    }
    if (!config.oauth2.failureRedirect) {
      throw new Error(
        "OAuth2 failureRedirect is required when OAuth2 is enabled"
      );
    }
    if (config.oauth2.autoProvision && !config.userService.createUser) {
      throw new Error(
        "UserService.createUser is required when OAuth2 autoProvision is enabled"
      );
    }
  }

  configurations = config;
  const logger = createLogger(config);
  logger.info("AuthCore module initialized");
  const router = express.Router();

  // Set up routes if JWT is enabled
  if (config.jwt && config.jwt.enabled) {
    jwtRoutes(router, configurations);
    logger.info("JWT routes enabled");
  }

  // Set up routes if session is enabled
  if (config.session && config.session.enabled) {
    setupSession(router, configurations);
    sessionRoutes(router, configurations);
    logger.info("Session routes enabled");
  }

  // Set up OAuth if enabled - SETUP BEFORE ROUTES
  if (config.oauth2?.enabled) {
    router.use(passport.initialize());
    oauth2Config(config, logger);
    oauth2Routes(router, config);
    logger.info("OAuth routes enabled");
  }

  return router;
}

// Middleware function for verifying authentication
function verify(
  permission?: string
): (req: Request, res: Response, next: NextFunction) => void {
  return (req: Request, res: Response, next: NextFunction) => {
    const { jwt, session } = configurations;
    const logger = createLogger(configurations);

    // Ensure user has permissions
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const checkPermission = (user: any) => {
      if (permission && (!user.grants || !user.grants.includes(permission))) {
        logger.warn(
          `Access denied: Missing required permission (${permission}) for user: ${
            user.username || "unknown"
          }`
        );
        return res.status(403).json({
          error: "Access denied: Missing required permission",
          required: permission,
          userGrants: user.grants || [],
        });
      }
      return next();
    };

    if (jwt && jwt.enabled) {
      return jwtMiddleware(configurations)(req, res, (err) => {
        if (err) {
          logger.warn("JWT verification failed", { error: err.message });
          return res.status(403).json({ error: "Token is invalid or expired" });
        }
        return checkPermission(req.user);
      });
    } else if (session && session.enabled) {
      return sessionMiddleware(configurations)(req, res, (err) => {
        if (err) {
          logger.warn("Session verification failed", { error: err.message });
          return res.status(403).json({ error: "Invalid session" });
        }
        return checkPermission(req.user);
      });
    } else {
      logger.warn(
        "Either JWT or session should be configured to use verify middleware"
      );
      return res.status(500).json({ error: "Authentication not configured" });
    }
  };
}

// Export the main functions
export default { config, verify };
