/* eslint-disable @typescript-eslint/no-explicit-any */
import { NextFunction, Request, Response, Router } from "express";
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

  // Routes for Custom OAuth Strategies
  if (!config.oauth2?.providers) return;

  Object.entries(config.oauth2.providers).forEach(
    ([providerName, providerConfig]) => {
      try {
        logger.info(`Setting up routes for custom provider: ${providerName}`);

        // Auth initiation route - simple popup
        router.get(
          `${basePrefix}/${providerName}`,
          (req: Request, res: Response, next: NextFunction) => {
            const redirect_uri = req.query.redirect_uri as string;

            // Store redirect_uri in session for callback
            if (req.session && redirect_uri) {
              req.session.oauthRedirectUri = redirect_uri;
            }

            logger.info(`Initiating ${providerName} OAuth flow`, {
              redirect_uri,
            });

            const authenticator = passport.authenticate(providerName, {
              scope: providerConfig?.scope || ["profile", "email"],
            } as any);

            authenticator(req, res, next);
          }
        );

        // Auth callback route - simple redirect back to frontend
        router.get(
          `${basePrefix}/${providerName}/callback`,
          (req: Request, res: Response, next: NextFunction) => {
            const { error } = req.query;

            if (error) {
              logger.error(`OAuth provider error: ${error}`);
              return handleOAuthError(res, error as string);
            }

            next();
          },
          // Passport authentication
          (req: Request, res: Response, next: NextFunction) => {
            passport.authenticate(providerName, {
              session: false,
              failureRedirect: "/auth/error",
            } as any)(req, res, next);
          },
          // Simple callback handler
          async (req: Request, res: Response) => {
            try {
              const redirectUri = req.session?.oauthRedirectUri;

              // Clean up session
              if (req.session) {
                delete req.session.oauthRedirectUri;
              }

              logger.info(`Handling ${providerName} OAuth callback`, {
                hasUser: !!req.user,
                redirectUri,
              });

              if (!req.user) {
                logger.error("User data missing in OAuth callback");
                return handleOAuthError(res, "user_data_missing");
              }

              let authResult;

              // Use existing module logic - exactly like your JWT/Session routes
              if (config.jwt?.enabled) {
                authResult = createJwtTokens(config.jwt, req.user as User);
                logger.info("JWT tokens created for OAuth user");
              } else if (config.session?.enabled) {
                authResult = createSessionPayload(req.user as User);
                req.session.user = authResult;
                logger.info("Session created for OAuth user");
              } else {
                logger.error("No authentication method configured");
                return handleOAuthError(res, "auth_not_configured");
              }

              // Simple redirect back to frontend with tokens
              if (redirectUri) {
                return redirectToFrontend(
                  res,
                  authResult,
                  redirectUri,
                  providerName
                );
              }

              // Fallback: return JSON response (for API clients)
              res.json(
                apiResponse(201, `${providerName} OAuth Successful`, true, [
                  authResult,
                ])
              );
            } catch (err: any) {
              logger.error(`Error during ${providerName} OAuth callback`, {
                error: err.message,
              });

              handleOAuthError(res, err.message);
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

  // Simple error route
  router.get("/auth/error", (req: Request, res: Response) => {
    const { error } = req.query;

    // Return HTML that communicates with parent window
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
          <title>Authentication Failed</title>
      </head>
      <body>
          <script>
              if (window.opener && !window.opener.closed) {
                  window.opener.postMessage({
                      type: 'OAUTH_ERROR',
                      error: '${error || "Authentication failed"}'
                  }, window.opener.location.origin);
                  window.close();
              }
          </script>
      </body>
      </html>
    `);
  });
};

// Simple redirect to frontend with tokens
const redirectToFrontend = (
  res: Response,
  authResult: any,
  redirectUri: string,
  provider: string
) => {
  const url = new URL(redirectUri);

  // Add tokens to URL (frontend will remove them)
  if (authResult.accessToken) {
    url.searchParams.set("access_token", authResult.accessToken);
  }
  if (authResult.refreshToken) {
    url.searchParams.set("refresh_token", authResult.refreshToken);
  }
  if (authResult.user) {
    url.searchParams.set("user", JSON.stringify(authResult.user));
  }

  // Add metadata
  url.searchParams.set("provider", provider);
  url.searchParams.set("success", "true");

  // Return HTML that sends tokens to parent window and closes
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>Authentication Successful</title>
    </head>
    <body>
        <script>
            // Send tokens to parent window
            if (window.opener && !window.opener.closed) {
                window.opener.postMessage({
                    type: 'OAUTH_SUCCESS',
                    access_token: '${authResult.accessToken || ""}',
                    refresh_token: '${authResult.refreshToken || ""}',
                    user: ${
                      authResult.user ? JSON.stringify(authResult.user) : "null"
                    },
                    provider: '${provider}'
                }, window.opener.location.origin);
            }

            // Close popup
            setTimeout(() => window.close(), 500);
        </script>
    </body>
    </html>
  `);
};

// Simple error handler
const handleOAuthError = (res: Response, error: string) => {
  res.redirect(`/auth/error?error=${encodeURIComponent(error)}`);
};
