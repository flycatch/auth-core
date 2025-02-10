const express = require("express");
const createLogger = require("./lib/wintson.logger");
const jwtRoutes = require("./routes/jwt");
const sessionRoutes = require("./routes/session");
const setupGoogleRoutes = require("./routes/setup-google-oath");
const setupSession  = require("./config/setupSession");
const setupGoogleOath  = require("./config/setupGoogleOath");
const jwtMiddleware  = require("./middlewares/jwtMiddleware");
const sessionMiddleware  = require("./middlewares/sessionMiddleware");
const googleAuthMiddleware  = require("./middlewares/googleAuthMiddleware");
const userRoutes = require("./routes/user");

// Configuration storage
let configurations = {};

// Function to initialize configurations and set up routes
function config(config) {
  configurations = config;

  const logger = createLogger(config);
  logger.info('Info logs enabled'); // Will be shown only if logs: true

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

  // Register /me route
  userRoutes(router, configurations);


  return router;
}

// Middleware function for verifying authentication
function verify(permission) {
  return (req, res, next) => {
    const { jwt, session, google } = configurations;

    //  Ensure user has permissions
    const checkPermission = (user) => {
      if (permission && (!user.grands || !user.grands.includes(permission))) {
        logger.warn(`Access denied: Missing required permission (${permission})`);
        return res.status(403).json({ error: "Access denied: Missing required permission" });
      }
      return next();
    };


    if (jwt && jwt.enabled) {
      return jwtMiddleware(configurations)(req, res,(err) => {

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
          logger.warn("Google OAuth verification failed", { error: err.message });
          return res.status(403).json({ error: "Google OAuth token is invalid or expired" });
        }
        checkPermission(req.user);
      });
    
    } else {
      logger.warn("Authentication is not configured");
      return res.status(500).json({ error: "Authentication not configured" });
    }
  };
}

module.exports = { config, verify };