import { NextFunction, Request, Response, Router } from "express";
import { Config } from "./interfaces/config.interface";
import express from "express";
import createLogger from "./lib/wintson.logger";
import jwtRoutes from "./routes/jwt.routes";
import sessionRoutes from "./routes/session.routes";
import setupGoogleRoutes from "./routes/setup-google-oath.routes";
import setupSession from "./config/Session.config";
import setupGoogleOath from "./config/GoogleOath.config";
import jwtMiddleware from "./middlewares/jwt.middleware";
import sessionMiddleware from "./middlewares/session.middleware";
import googleAuthMiddleware from "./middlewares/googleAuth.middleware";

// Configuration storage
let configurations: Config = {} as Config;

// Function to initialize configurations and set up routes
function config(config: Config): Router {
  configurations = config;

  const logger = createLogger(config);
  logger.info("Info logs enabled"); // Will be shown only if logs: true

  const router = express.Router();

  // Set up routes if JWT is enabled
  if (config.jwt && config.jwt.enabled) {
    jwtRoutes(router, configurations);
  }

  // Set up routes if session is enabled
  if (config.session && config.session.enabled) {
    setupSession(router, configurations);
    sessionRoutes(router, configurations);
  }

  // Set up routes if Google OAuth is enabled
  if (config.google && config.google.enabled) {
    setupGoogleOath(config);
    setupGoogleRoutes(router, config);
  }

  return router;
}

// Middleware function for verifying authentication
function verify(
  permission?: string
): (req: Request, res: Response, next: NextFunction) => void {
  return (req: Request, res: Response, next: NextFunction) => {
    const { jwt, session, google } = configurations;
    const logger = createLogger(configurations);

    //  Ensure user has permissions
    const checkPermission = (user: any) => {
      if (permission && (!user.grands || !user.grands.includes(permission))) {
        logger.warn(
          `Access denied: Missing required permission (${permission})`
        );
        return res
          .status(403)
          .json({ error: "Access denied: Missing required permission" });
      }
      return next();
    };

    if (jwt && jwt.enabled) {
      return jwtMiddleware(configurations)(req, res, (err) => {
        if (err) {
          logger.warn("JWT verification failed", { error: err.message });
          return res.status(403).json({ error: "Token is invalid or expired" });
        }
        checkPermission(req.user);
      });
    } else if (session && session.enabled) {
      return sessionMiddleware(configurations)(req, res, (err) => {
        if (err) {
          logger.warn("Session verification failed", { error: err.message });
          return res.status(403).json({ error: "Invalid session" });
        }
        checkPermission(req.user);
      });
    } else if (google && google.enabled) {
      return googleAuthMiddleware(configurations)(req, res, (err) => {
        if (err) {
          logger.warn("Google OAuth verification failed", {
            error: err.message,
          });
          return res
            .status(403)
            .json({ error: "Google OAuth token is invalid or expired" });
        }
        checkPermission(req.user);
      });
    } else {
      logger.warn("Authentication is not configured");
      return res.status(500).json({ error: "Authentication not configured" });
    }
  };
}

export default { config, verify };
