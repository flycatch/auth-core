/* eslint-disable @typescript-eslint/no-explicit-any */
import { NextFunction, Request, Response, Router } from "express";
import { Config, OAuth2CallbackInfo } from "../interfaces/config.interface";
import passport from "passport";
import createLogger from "../lib/winston.logger";
import { createJwtTokens } from "../utils/jwt";
import { User } from "../interfaces/user.interface";
import { createSessionPayload } from "../utils/session";
import crypto from "crypto";

// In-memory store for temporary authorization codes
// In production, use Redis or a database with TTL
const authCodeStore = new Map<string, { user: User; expiresAt: number }>();

// Cleanup expired codes every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [code, data] of authCodeStore.entries()) {
    if (data.expiresAt < now) {
      authCodeStore.delete(code);
    }
  }
}, 5 * 60 * 1000);

/**
 * OAuth2 Routes
 * Sets up authentication and callback routes for each configured OAuth provider
 */
export default (router: Router, config: Config) => {
  if (!config.oauth2?.enabled) return;

  const logger = createLogger(config);
  const basePrefix = config.oauth2.prefix || "/auth";

  if (!config.oauth2?.providers) return;

  // Iterate over each OAuth provider to setup routes
  Object.entries(config.oauth2.providers).forEach(
    ([providerName, providerConfig]) => {
      try {
        logger.info(`Setting up routes for custom provider: ${providerName}`);

        /**
         * Auth initiation route
         * Redirects user to provider's OAuth consent screen
         */
        router.get(
          `${basePrefix}/${providerName}`,
          (req: Request, res: Response, next: NextFunction) => {
            logger.info(`Initiating ${providerName} OAuth flow`);

            const authenticator = passport.authenticate(providerName, {
              scope: providerConfig?.scope || ["profile", "email"],
            } as any);

            authenticator(req, res, next);
          }
        );

        /**
         * Auth callback route
         * Handles provider's response after user authentication
         */
        router.get(
          `${basePrefix}/${providerName}/callback`,
          // Check for provider error in query params
          (req: Request, res: Response, next: NextFunction) => {
            const { error, error_description } = req.query;

            if (error) {
              logger.error(
                `OAuth provider error: ${error} - ${error_description}`
              );
              return handleOAuthFailure(
                res,
                config,
                providerName,
                error as string,
                error_description as string
              );
            }

            next();
          },
          // Passport authentication middleware
          (req: Request, res: Response, next: NextFunction) => {
            passport.authenticate(providerName, {
              session: false,
              failureRedirect: `${basePrefix}/error`,
            } as any)(req, res, next);
          },
          // Success handler - Generate temporary code
          async (req: Request, res: Response) => {
            try {
              logger.info(`Handling ${providerName} OAuth callback`, {
                hasCallbackInfo: !!req.user,
              });

              if (!req.user) {
                logger.error("Callback info missing in OAuth callback");
                return handleOAuthFailure(
                  res,
                  config,
                  providerName,
                  "callback_data_missing",
                  "OAuth callback data not found"
                );
              }

              const callbackInfo = req.user as OAuth2CallbackInfo;
              let user: User;

              // Call the onSuccess callback if provided
              if (config.oauth2?.onSuccess) {
                try {
                  logger.info("Calling onSuccess callback");
                  user = await config.oauth2.onSuccess(callbackInfo);

                  if (!user) {
                    logger.error("onSuccess callback did not return a user");
                    return handleOAuthFailure(
                      res,
                      config,
                      providerName,
                      "user_creation_failed",
                      "Failed to create or retrieve user"
                    );
                  }

                  // Apply default role if configured and user has no grants
                  if (
                    config.oauth2.defaultRole &&
                    (!user.grants || user.grants.length === 0)
                  ) {
                    user.grants = [config.oauth2.defaultRole];
                    logger.info(
                      `Assigned default role: ${config.oauth2.defaultRole}`
                    );
                  }
                } catch (err: any) {
                  logger.error("Error in onSuccess callback", {
                    error: err.message,
                    stack: err.stack,
                  });
                  return handleOAuthFailure(
                    res,
                    config,
                    providerName,
                    "callback_error",
                    err.message
                  );
                }
              } else {
                // Fallback to existing user or fail
                if (callbackInfo.existingUser) {
                  user = callbackInfo.existingUser;
                  logger.info("Using existing user (no onSuccess callback)");
                } else {
                  logger.warn(
                    "No onSuccess callback and no existing user found"
                  );
                  return handleOAuthFailure(
                    res,
                    config,
                    providerName,
                    "user_not_found",
                    "User not found and no onSuccess callback configured"
                  );
                }
              }

              // Ensure provider info is set
              user.provider = callbackInfo.provider;
              user.providerId = callbackInfo.profile.providerId;

              // Generate temporary authorization code
              const authCode = crypto.randomBytes(32).toString("hex");
              const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes

              // Store user data with the code
              authCodeStore.set(authCode, { user, expiresAt });
              logger.info("Temporary auth code generated", { authCode });

              // Redirect to frontend with the code
              return handleOAuthSuccess(res, config, providerName, authCode);
            } catch (err: any) {
              logger.error(`Error during ${providerName} OAuth callback`, {
                error: err.message,
                stack: err.stack,
              });
              handleOAuthFailure(
                res,
                config,
                providerName,
                "internal_error",
                err.message
              );
            }
          }
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

  /**
   * Token exchange endpoint
   * Frontend calls this with the authorization code to get actual tokens
   */
  router.post(`${basePrefix}/token`, async (req: Request, res: Response) => {
    try {
      const { code } = req.body;

      if (!code) {
        logger.warn("Token exchange attempted without code");
        return res.status(400).json({ error: "Authorization code required" });
      }

      // Retrieve user data from code
      const codeData = authCodeStore.get(code);

      if (!codeData) {
        logger.warn("Invalid or expired authorization code", { code });
        return res.status(401).json({ error: "Invalid or expired code" });
      }

      // Check expiration
      if (codeData.expiresAt < Date.now()) {
        authCodeStore.delete(code);
        logger.warn("Expired authorization code used", { code });
        return res.status(401).json({ error: "Code expired" });
      }

      const user = codeData.user;

      // Delete code after use (one-time use)
      authCodeStore.delete(code);
      logger.info("Authorization code exchanged successfully");

      /**
       * JWT Authentication
       */
      if (config.jwt?.enabled) {
        const { refreshToken, accessToken } = createJwtTokens(config.jwt, user);

        logger.info("JWT tokens created for OAuth user");

        const response: any = {
          success: true,
          user,
          accessToken,
        };

        if (config.jwt?.refresh && refreshToken) {
          response.refreshToken = refreshToken;

          // Set refresh token as httpOnly cookie
          res.cookie("AuthRefreshToken", refreshToken, {
            httpOnly: true,
            secure: true,
            sameSite: "strict",
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
            path: "/",
          });
          logger.info("Refresh token set as httpOnly cookie");
        }

        return res.json(response);

        /**
         * Session-based Authentication
         */
      } else if (config.session?.enabled) {
        const sessionPayload = createSessionPayload(user);
        req.session.user = sessionPayload;

        logger.info("Session created for OAuth user");

        // Save session before sending response
        req.session.save((err) => {
          if (err) {
            logger.error("Failed to save session", { error: err.message });
            return res.status(500).json({ error: "Failed to create session" });
          }

          return res.json({
            success: true,
            user,
            sessionId: req.sessionID,
          });
        });
      } else {
        logger.error("No authentication method configured");
        return res.status(500).json({ error: "Authentication not configured" });
      }
    } catch (err: any) {
      logger.error("Error during token exchange", {
        error: err.message,
        stack: err.stack,
      });
      return res.status(500).json({ error: "Internal server error" });
    }
  });

  /**
   * Internal error route
   */
  router.get(`${basePrefix}/error`, (req: Request, res: Response) => {
    const { error, error_description, provider } = req.query;
    const errorMessage = error_description || error || "Authentication failed";

    if (config.oauth2?.onFailure) {
      config.oauth2.onFailure(
        (error as string) || "unknown_error",
        errorMessage as string,
        (provider as string) || "unknown"
      );
    }

    const failureUrl = new URL(config.oauth2!.failureRedirect);
    failureUrl.searchParams.set("error", (error as string) || "unknown_error");
    failureUrl.searchParams.set("error_description", errorMessage as string);
    if (provider) {
      failureUrl.searchParams.set("provider", provider as string);
    }

    res.redirect(failureUrl.toString());
  });
};

/**
 * Handle OAuth success - redirect with authorization code
 */
const handleOAuthSuccess = (
  res: Response,
  config: Config,
  providerName: string,
  authCode: string
) => {
  const successUrl = new URL(config.oauth2!.successRedirect);

  successUrl.searchParams.set("provider", providerName);
  successUrl.searchParams.set("code", authCode);

  res.redirect(successUrl.toString());
};

/**
 * Handle OAuth failure
 */
const handleOAuthFailure = (
  res: Response,
  config: Config,
  provider: string,
  error: string,
  errorDescription?: string
) => {
  if (config.oauth2?.onFailure) {
    config.oauth2.onFailure(error, errorDescription || "", provider);
  }

  const failureUrl = new URL(config.oauth2!.failureRedirect);
  failureUrl.searchParams.set("error", error);
  failureUrl.searchParams.set("provider", provider);
  if (errorDescription) {
    failureUrl.searchParams.set("error_description", errorDescription);
  }

  res.redirect(failureUrl.toString());
};
