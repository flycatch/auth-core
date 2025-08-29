/* eslint-disable @typescript-eslint/no-explicit-any */
import { Request, Response, Router } from "express";
import { Config } from "../interfaces/config.interface";
import passport from "passport";
import apiResponse from "../utils/api-response";
import createLogger from "../lib/wintson.logger";
import { createJwtTokens } from "../utils/jwt";
import { User } from "../interfaces/user.interface";
import { createSessionPayload } from "../utils/session";

export default (router: Router, config: Config) => {
  if (!config.oauth?.enabled) return;

  const logger = createLogger(config);
  const basePrefix = config.oauth.prefix || "/auth";

  // Google routes
  if (config.oauth.providers.google) {
    router.get(
      `${basePrefix}/google`,
      passport.authenticate("google", { scope: ["profile", "email"] })
    );

    router.get(
      `${basePrefix}/google/callback`,
      passport.authenticate("google", { session: false }),
      createCallbackHandler("google", config, logger)
    );
  }

  // Facebook routes
  if (config.oauth.providers.facebook) {
    router.get(
      `${basePrefix}/facebook`,
      passport.authenticate("facebook", { scope: ["email"] })
    );

    router.get(
      `${basePrefix}/facebook/callback`,
      passport.authenticate("facebook", { session: false }),
      createCallbackHandler("facebook", config, logger)
    );
  }

  // Github Routes
  if (config.oauth.providers.github) {
    router.get(
      `${basePrefix}/github`,
      passport.authenticate("github", { scope: ["email"] })
    );

    router.get(
      `${basePrefix}/github/callback`,
      passport.authenticate("github", { session: false }),
      createCallbackHandler("github", config, logger)
    );
  }

  // Twitter Routes
  if (config.oauth.providers.twitter) {
    router.get(
      `${basePrefix}/twitter`,
      (req: Request, res: Response, next) => {
        logger.info("Initiating Twitter OAuth2 flow");
        next();
      },
      passport.authenticate("twitter", {
        scope: ["tweet.read", "users.read", "offline.access"],
      })
    );

    router.get(
      `${basePrefix}/twitter/callback`,
      (req: Request, res: Response, next) => {
        logger.info("Twitter OAuth2 callback received", {
          query: req.query,
          url: req.url,
        });
        next();
      },
      passport.authenticate("twitter", {
        session: false,
        failureRedirect: "/auth/error",
      }),
      createCallbackHandler("twitter", config, logger)
    );
  }

  // Routes for Custum Oauth Startegies
  setupCustomProviderRoutes(router, config, logger, basePrefix);

  // Error route for failed OAuth
  router.get("/auth/error", (req: Request, res: Response) => {
    logger.error("OAuth authentication failed");
    res.status(400).json({
      error: "Authentication failed",
      message: "OAuth authentication was unsuccessful",
    });
  });
};

const createCallbackHandler = (
  provider: string,
  config: Config,
  logger: any
) => {
  return async (req: Request, res: Response) => {
    try {
      logger.info(`Handling ${provider} OAuth callback`);

      if (!req.user) {
        logger.error("User Data Missed on callback");
        return res.status(500).json({ error: "Something went wrong" });
      }

      if (config.jwt?.enabled) {
        const jwtTokens = createJwtTokens(config.jwt, req.user as User);
        logger.info("User successfully logged in with OAuth");
        res.json(
          apiResponse(201, `${provider} OAuth Successful`, true, [jwtTokens])
        );
      } else if (config.session?.enabled) {
        const payload = createSessionPayload(req.user as User);
        req.session.user = payload;

        logger.info("Session login successful");
        return res.json(apiResponse(201, "Login Successful", true, [payload]));
      } else {
        logger.error("Either JWT or Session should be configured");
        res.status(500).json({
          error: "Either JWT or Session auth configured to use OAuth",
        });
      }
    } catch (err: any) {
      logger.error(`Error during ${provider} OAuth callback`, {
        error: err.message,
        stack: err.stack,
      });
      res.status(500).json(apiResponse(500, "Internal server error", false));
    }
  };
};

// Setup routes for custom providers
const setupCustomProviderRoutes = (
  router: Router,
  config: Config,
  logger: any,
  basePrefix: string
) => {
  if (!config.oauth?.customProviders) return;

  Object.entries(config.oauth.customProviders).forEach(
    ([providerName, providerConfig]) => {
      try {
        logger.info(`Setting up routes for custom provider: ${providerName}`);

        // Auth initiation route
        router.get(
          `${basePrefix}/${providerName}`,
          (req: Request, res: Response, next) => {
            logger.info(`Initiating ${providerName} OAuth flow`);
            next();
          },
          passport.authenticate(providerName, {
            scope: providerConfig.scope || ["profile", "email"],
          })
        );

        // Auth callback route
        router.get(
          `${basePrefix}/${providerName}/callback`,
          (req: Request, res: Response, next) => {
            logger.info(`${providerName} OAuth callback received`, {
              query: req.query,
              url: req.url,
            });
            next();
          },
          passport.authenticate(providerName, {
            session: false,
            failureRedirect: "/auth/error",
          }),
          createCallbackHandler(providerName, config, logger)
        );

        logger.info(`Custom provider ${providerName} routes setup complete`);
      } catch (error) {
        logger.error(
          `Failed to setup routes for custom provider ${providerName}:`,
          error
        );
      }
    }
  );
};
