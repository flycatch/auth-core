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
  if (!config.oauth2?.enabled) return;

  const logger = createLogger(config);
  const basePrefix = config.oauth2.prefix || "/auth";

  // Routes for Custum Oauth Startegies
  if (!config.oauth2?.providers) return;

  Object.entries(config.oauth2.providers).forEach(
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
