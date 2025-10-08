/* eslint-disable @typescript-eslint/no-explicit-any */
import { Request, Response, Router } from "express";
import { Config } from "../interfaces/config.interface";
import passport from "passport";
import apiResponse from "../utils/api-response";
import createLogger from "../lib/wintson.logger";
import { createJwtTokens } from "../utils/jwt";
import { User } from "../interfaces/user.interface";
import { createSessionPayload } from "../utils/session";
import crypto from "crypto";

export default (router: Router, config: Config) => {
  if (!config.oauth2?.enabled) return;

  const logger = createLogger(config);
  const basePrefix = config.oauth2.prefix || "/auth";

  // Routes for Custom Oauth Strategies
  if (!config.oauth2?.providers) return;

  Object.entries(config.oauth2.providers).forEach(
    ([providerName, providerConfig]) => {
      try {
        logger.info(`Setting up routes for custom provider: ${providerName}`);

        // Auth initiation route - Support redirectUrl parameter
        router.get(
          `${basePrefix}/${providerName}`,
          (req: Request, res: Response, next) => {
            const redirectUrl = req.query.redirectUrl as string;
            const state = crypto.randomBytes(16).toString("hex");

            logger.info(`Initiating ${providerName} OAuth flow`, {
              redirectUrl,
              provider: providerName,
            });

            // Store state and redirectUrl in session for callback handling
            if (req.session) {
              req.session.oauthState = state;
              req.session.oauthRedirectUrl = redirectUrl;
              req.session.oauthProvider = providerName;
            }

            // Add state parameter to authentication
            const authenticator = passport.authenticate(providerName, {
              scope: providerConfig?.scope || ["profile", "email"],
              state: state,
            });

            authenticator(req, res, next);
          }
        );

        // Auth callback route - Handle redirect back to FE
        router.get(
          `${basePrefix}/${providerName}/callback`,
          (req: Request, res: Response, next) => {
            const { state, code, error } = req.query;
            const sessionState = req.session?.oauthState;
            const redirectUrl = req.session?.oauthRedirectUrl;
            const provider = req.session?.oauthProvider;

            logger.info(`${providerName} OAuth callback received`, {
              state,
              hasCode: !!code,
              hasError: !!error,
              redirectUrl,
              sessionProvider: provider,
            });

            // Validate state parameter for security
            if (state !== sessionState) {
              logger.warn(`State parameter mismatch for ${providerName}`);
              if (redirectUrl) {
                return res.redirect(`${redirectUrl}?error=invalid_state`);
              }
              return res.status(400).json({ error: "Invalid state parameter" });
            }

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
    const redirectUrl = req.session?.oauthRedirectUrl;
    const error = req.query.error || "Authentication failed";

    logger.error("OAuth authentication failed", { error, redirectUrl });

    if (redirectUrl) {
      return res.redirect(
        `${redirectUrl}?error=${encodeURIComponent(error.toString())}`
      );
    }

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
      const redirectUrl = req.session?.oauthRedirectUrl;

      // Clean up session
      if (req.session) {
        delete req.session.oauthState;
        delete req.session.oauthRedirectUrl;
        delete req.session.oauthProvider;
      }

      logger.info(`Handling ${provider} OAuth callback`, { redirectUrl });

      if (!req.user) {
        logger.error("User Data Missed on callback");
        if (redirectUrl) {
          return res.redirect(`${redirectUrl}?error=user_data_missing`);
        }
        return res.status(500).json({ error: "Something went wrong" });
      }

      let authResult;

      if (config.jwt?.enabled) {
        authResult = createJwtTokens(config.jwt, req.user as User);
        logger.info("User successfully logged in with OAuth");
      } else if (config.session?.enabled) {
        authResult = createSessionPayload(req.user as User);
        req.session.user = authResult;
        logger.info("Session login successful");
      } else {
        logger.error("Either JWT or Session should be configured");
        if (redirectUrl) {
          return res.redirect(`${redirectUrl}?error=auth_not_configured`);
        }
        return res.status(500).json({
          error: "Either JWT or Session auth configured to use OAuth",
        });
      }

      // If redirectUrl provided, redirect back to FE with tokens
      if (redirectUrl) {
        const url = new URL(redirectUrl);

        // Add tokens as query parameters
        if ("accessToken" in authResult && authResult.accessToken) {
          url.searchParams.set("accessToken", authResult.accessToken);
        }
        if ("refreshToken" in authResult && authResult.refreshToken) {
          url.searchParams.set("refreshToken", authResult.refreshToken);
        }
        if ("user" in authResult && authResult.user) {
          url.searchParams.set("user", JSON.stringify(authResult.user));
        }

        logger.info(`Redirecting to FE: ${url.toString()}`);
        return res.redirect(url.toString());
      }

      // If no redirectUrl, return JSON response (API mode)
      res.json(
        apiResponse(201, `${provider} OAuth Successful`, true, [authResult])
      );
    } catch (err: any) {
      logger.error(`Error during ${provider} OAuth callback`, {
        error: err.message,
        stack: err.stack,
      });

      const redirectUrl = req.session?.oauthRedirectUrl;
      if (redirectUrl) {
        return res.redirect(
          `${redirectUrl}?error=${encodeURIComponent(err.message)}`
        );
      }

      res.status(500).json(apiResponse(500, "Internal server error", false));
    }
  };
};
