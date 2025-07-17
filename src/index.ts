import jsonWebToken, { VerifyErrors } from "jsonwebtoken";
import { NextFunction, Request, Response, Router } from "express";
import session from "express-session";
import logger from "./lib/wintson.logger";
import jwtRoutes from "./routes/jwt";
import sessionRoutes from "./routes/session";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import setupGoogleRoutes from "./routes/setup-google-oath";
import Config from "./interfaces/config.interface";
import JWTPayload from "./interfaces/jwt.interface";

class AuthCore {
  configurations: {};
  router: Router;
  constructor() {
    this.configurations = {};
    this.router = Router();
  }

  config(config: Config) {
    this.configurations = config;

    // Automatically set up routes if JWT is enabled
    if (config.jwt && config.jwt.enabled) {
      jwtRoutes(this.router, config);
    }
    // Automatically set up routes if session is enabled
    if (config.session && config.session.enabled) {
      this.setupSession(config);
      sessionRoutes(this.router, config);
    }
    // Automatically set up routes if google is enabled
    if (config.google && config.google.enabled) {
      this.setupGoogleOath(config);
      setupGoogleRoutes(this.router, config);
    }
    return this.router;
  }

  setupSession(config: Config) {
    if (!config.session) {
      throw Error("Session configuration is Required");
    }
    const { secret, resave, saveUninitialized, cookie } = config.session;

    this.router.use(
      session({
        secret: secret || "Default_secret",
        resave: resave || false,
        saveUninitialized: saveUninitialized || true,
        cookie: {
          secure: cookie?.secure || false,
          maxAge: cookie?.maxAge || 24 * 60 * 60 * 1000, // 1 day
        },
      })
    );
  }

  setupGoogleOath(config: Config) {
    if (!config.google) {
      throw Error("Google configuration is Required");
    }
    passport.use(
      new GoogleStrategy(
        {
          clientID: config.google.clientID,
          clientSecret: config.google.clientSecret,
          callbackURL: config.google.callbackURL,
        },
        async (accessToken, refreshToken, profile, done) => {
          try {
            logger.info("Google OAuth strategy triggered");
            logger.debug(`Access Token: ${accessToken}`);
            logger.debug(`Refresh Token: ${refreshToken}`);
            logger.debug(`Google Profile: ${JSON.stringify(profile)}`);

            const email = profile.emails?.[0]?.value;
            if (!email) {
              logger.warn("No email found in Google profile");
              return done(null, false, { message: "Email is required" });
            }
            logger.info(`Processing Google OAuth for email: ${email}`);

            // Check for user existence in DB
            const user = await config.userService.loadUser(email);
            if (!user) {
              logger.warn(`User not found for email: ${email}`);
              return done(null, false, { message: "User not authorized" });
            }

            logger.info(`User successfully authenticated: ${user.username}`);
            return done(null, user);
          } catch (err: any) {
            logger.error("Error in Google OAuth strategy", {
              error: err.message,
            });
            return done(err, false, { message: "Something went wrong" });
          }
        }
      )
    );

    // Serialize and deserialize user
    passport.serializeUser((user, done) => {
      logger.info(`Serializing user: ${user.username}`);
      done(null, user);
    });

    passport.deserializeUser((user: Express.User, done) => {
      logger.info(`Deserializing user: ${user.username}`);
      done(null, user);
    });
  }

  verify() {
    return (req: Request, res: Response, next: NextFunction) => {
      const { jwt, session, google } = this.configurations as Config;

      // Check if JWT and Session are both enabled
      if (jwt && jwt.enabled && session && session.enabled) {
        const authHeader = req.headers["authorization"];

        // If JWT token is provided, prioritize JWT authentication
        if (authHeader) {
          logger.info("JWT header found, verifying...");
          const token = authHeader.split(" ")[1];

          jsonWebToken.verify(
            token,
            jwt.secret,
            (err: VerifyErrors | null, user: any) => {
              if (err) {
                logger.warn("Invalid or expired token", { error: err.message });
                return res
                  .status(403)
                  .json({ error: "Token is invalid or expired" });
              }

              logger.info(
                `JWT verified successfully for username: ${user?.username}`
              );
              req.user = user;
              return next();
            }
          );
        } else if (req.session && req.session.user) {
          // Fallback to session verification if no JWT token is found
          logger.info(
            `Session verified for username: ${req.session.user.username}`
          );
          req.user = req.session.user as Express.User;
          return next();
        } else {
          // If neither JWT nor session is valid
          logger.warn("Unauthorized access attempt");
          return res.status(401).json({ error: "Unauthorized" });
        }
      } else if (jwt && jwt.enabled) {
        // If only JWT is enabled
        const authHeader = req.headers["authorization"];
        if (authHeader) {
          logger.info("JWT only, verifying...");
          const token = authHeader.split(" ")[1];

          jsonWebToken.verify(
            token,
            jwt.secret,
            (err: VerifyErrors | null, user: any) => {
              if (err) {
                logger.warn("Invalid or expired token", { error: err.message });
                return res
                  .status(403)
                  .json({ error: "Token is invalid or expired" });
              }

              logger.info(
                `JWT verified successfully for username: ${user.username}`
              );
              req.user = user;
              return next();
            }
          );
        } else {
          logger.warn("Unauthorized access attempt");
          return res.status(401).json({ error: "Unauthorized" });
        }
      } else if (session && session.enabled) {
        // If only session is enabled
        if (req.session && req.session.user) {
          logger.info(
            `Session verified for username: ${req.session.user.username}`
          );
          req.user = req.session.user as Express.User;
          return next();
        } else {
          logger.warn("Unauthorized access attempt");
          return res.status(401).json({ error: "Unauthorized" });
        }
      } else if (google && google.enabled) {
        const authHeader = req.headers["authorization"];
        if (authHeader) {
          logger.info("JWT header found in google oath, verifying...");

          const token = authHeader.split(" ")[1];

          jsonWebToken.verify(
            token,
            google.secret,
            (err: VerifyErrors | null, user) => {
              if (err) {
                logger.warn("Invalid or expired token", { error: err.message });
                return res
                  .status(403)
                  .json({ error: "Token is invalid or expired" });
              }
              logger.info(
                `JWT verified successfully as google oath for username: ${
                  (user as JWTPayload).username
                }`
              );

              req.user = user as JWTPayload;
              next();
            }
          );
        } else {
          return res.status(401).json({ error: "Unauthorized" });
        }
      } else {
        // If neither JWT or google nor session is enabled
        logger.warn("Authentication is not configured");
        return res.status(500).json({ error: "Authentication not configured" });
      }
    };
  }
}
export const auth = new AuthCore();
// module.exports.default = auth; // Add a default export
// // export default new AuthCore();

// // module.exports = new AuthCore();

export { AuthCore }; // Add class for NestJS DI compatibility
export default auth;
