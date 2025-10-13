/* eslint-disable @typescript-eslint/no-explicit-any */
import { NextFunction, Request, Response, Router } from "express";
import { Config } from "../interfaces/config.interface";
import passport from "passport";
import createLogger from "../lib/wintson.logger";
import { createJwtTokens } from "../utils/jwt";
import { User } from "../interfaces/user.interface";
import { createSessionPayload } from "../utils/session";

export default (router: Router, config: Config) => {
  if (!config.oauth2?.enabled) return;

  const logger = createLogger(config);
  const basePrefix = config.oauth2.prefix || "/auth";

  // Routes for Custom OAuth Strategies
  if (!config.oauth2?.providers) return;

  Object.entries(config.oauth2.providers).forEach(
    ([providerName, providerConfig]) => {
      try {
        logger.info(`Setting up routes for custom provider: ${providerName}`);

        // Auth initiation route - redirects to provider
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

        // Auth callback route - handles provider response
        router.get(
          `${basePrefix}/${providerName}/callback`,
          (req: Request, res: Response, next: NextFunction) => {
            const { error, error_description } = req.query;

            if (error) {
              logger.error(
                `OAuth provider error: ${error} - ${error_description}`
              );
              return handleOAuthFailure(
                res,
                config,
                error as string,
                error_description as string
              );
            }

            next();
          },
          // Passport authentication
          (req: Request, res: Response, next: NextFunction) => {
            passport.authenticate(providerName, {
              session: false,
              failureRedirect: `${basePrefix}/error`, // Use internal error handler
            } as any)(req, res, next);
          },
          // Success handler
          async (req: Request, res: Response) => {
            try {
              logger.info(`Handling ${providerName} OAuth callback`, {
                hasUser: !!req.user,
              });

              if (!req.user) {
                logger.error("User data missing in OAuth callback");
                return handleOAuthFailure(
                  res,
                  config,
                  "user_data_missing",
                  "User data not found"
                );
              }

              const user = req.user as User;

              // Generate tokens based on configuration
              let authResult;
              let accessToken: string | undefined;
              let refreshToken: string | undefined;

              if (config.oauth2?.issueJwt !== false && config.jwt?.enabled) {
                // Include authorities/grants in JWT if configured
                const jwtPayload: any = {
                  provider: user.provider,
                  email: user.email,
                };

                if (
                  config.oauth2 &&
                  config.oauth2.includeAuthorities &&
                  user.grants
                ) {
                  jwtPayload.grants = user.grants;
                  // Extract roles if needed
                  const roles = user.grants.filter((grant: string | number) =>
                    String(grant).startsWith("ROLE_")
                  );
                  if (roles.length > 0) {
                    jwtPayload.roles = roles;
                  }
                }

                // Use the original 2-parameter function
                authResult = createJwtTokens(config.jwt, user);
                accessToken = authResult.accessToken;
                refreshToken = authResult.refreshToken;

                logger.info("JWT tokens created for OAuth user");
              } else if (config.session?.enabled) {
                authResult = createSessionPayload(user);
                req.session.user = authResult;
                logger.info("Session created for OAuth user");
              } else {
                logger.error("No authentication method configured");
                return handleOAuthFailure(
                  res,
                  config,
                  "auth_not_configured",
                  "Authentication method not configured"
                );
              }

              // Set refresh token as HTTP-only cookie if enabled
              if (
                config.oauth2?.setRefreshCookie &&
                refreshToken &&
                config.cookies?.enabled
              ) {
                setRefreshTokenCookie(res, refreshToken, config);
                logger.info("Refresh token set as HTTP-only cookie");
              }

              // Redirect to success URL
              return handleOAuthSuccess(
                res,
                config,
                providerName,
                accessToken,
                refreshToken,
                user
              );
            } catch (err: any) {
              logger.error(`Error during ${providerName} OAuth callback`, {
                error: err.message,
                stack: err.stack,
              });
              handleOAuthFailure(res, config, "internal_error", err.message);
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

  // Internal error route - redirects to failure URL
  router.get(`${basePrefix}/error`, (req: Request, res: Response) => {
    const { error, error_description } = req.query;
    const errorMessage = error_description || error || "Authentication failed";

    // Redirect to configured failure URL
    const failureUrl = new URL(config.oauth2!.failureRedirect);
    failureUrl.searchParams.set("error", (error as string) || "unknown_error");
    failureUrl.searchParams.set("error_description", errorMessage as string);

    res.redirect(failureUrl.toString());
  });
};

// Handle OAuth success
const handleOAuthSuccess = (
  res: Response,
  config: Config,
  providerName: string,
  accessToken?: string,
  refreshToken?: string,
  user?: User
) => {
  const successUrl = new URL(config.oauth2!.successRedirect);

  // Always add provider
  successUrl.searchParams.set("provider", providerName);

  // Add tokens to URL if configured
  if (config.oauth2!.appendTokensInRedirect) {
    if (accessToken) {
      successUrl.searchParams.set("accessToken", accessToken);
    }
    if (refreshToken) {
      successUrl.searchParams.set("refreshToken", refreshToken);
    }
  }

  // Add user info if available and tokens not appended (for session auth)
  if (user && !config.oauth2!.appendTokensInRedirect) {
    successUrl.searchParams.set("user", JSON.stringify(user));
  }

  res.redirect(successUrl.toString());
};

// Handle OAuth failure
const handleOAuthFailure = (
  res: Response,
  config: Config,
  error: string,
  errorDescription?: string
) => {
  const failureUrl = new URL(config.oauth2!.failureRedirect);
  failureUrl.searchParams.set("error", error);
  if (errorDescription) {
    failureUrl.searchParams.set("error_description", errorDescription);
  }

  res.redirect(failureUrl.toString());
};

// Set refresh token as HTTP-only cookie
const setRefreshTokenCookie = (
  res: Response,
  refreshToken: string,
  config: Config
) => {
  const cookieConfig = config.cookies || {};
  // Fix: Use proper type checking for cookie config
  const cookieName = (cookieConfig as any).name || "AuthRefreshToken";
  const httpOnly = (cookieConfig as any).httpOnly ?? true;
  const secure =
    (cookieConfig as any).secure ?? process.env.NODE_ENV === "production";
  const sameSite = (cookieConfig as any).sameSite || "Strict";
  const maxAge = (cookieConfig as any).maxAge || 7 * 24 * 60 * 60 * 1000; // 7 days
  const path = (cookieConfig as any).path || "/";

  res.cookie(cookieName, refreshToken, {
    httpOnly,
    secure,
    sameSite: sameSite as any,
    maxAge,
    path,
  });
};
