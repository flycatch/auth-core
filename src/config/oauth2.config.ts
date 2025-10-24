/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/no-explicit-any */
import passport from "passport";
import {
  Config,
  OAuth2CallbackInfo,
  ProviderConfig,
} from "../interfaces/config.interface";
import { OAuthUserProfile } from "../interfaces/user.interface";

/**
 * Initializes and configures all OAuth2 providers defined in the configuration.
 * Validates provider settings, sets up Passport strategies, and handles user provisioning.
 *
 * @param config - Application configuration object
 * @param logger - Logger instance for logging setup and errors
 */
export default (config: Config, logger: any) => {
  if (!config.oauth2?.enabled || !config.oauth2?.providers) {
    logger.warn("OAuth2 is not enabled or no providers configured");
    return;
  }

  if (!config.oauth2.successRedirect) {
    throw new Error("OAuth2 successRedirect is required");
  }
  if (!config.oauth2.failureRedirect) {
    throw new Error("OAuth2 failureRedirect is required");
  }

  Object.entries(config.oauth2.providers).forEach(
    ([providerName, providerConfig]) => {
      try {
        if (!providerConfig) {
          throw new Error(`Provider config missing for ${providerName}`);
        }

        validateProviderConfig(providerName, providerConfig);
        setupOauth2Provider(providerName, providerConfig, config, logger);
      } catch (error: any) {
        logger.error(
          `Failed to setup OAuth 2.0 provider for ${providerName}:`,
          {
            error: error.message,
            stack: error.stack,
          }
        );
        throw error;
      }
    }
  );

  logger.info("All OAuth 2.0 providers setup complete");
};

/**
 * Validates individual OAuth2 provider configuration.
 */
const validateProviderConfig = (
  providerName: string,
  config: ProviderConfig
) => {
  if (!config.clientID) {
    throw new Error(`clientID is required for ${providerName} provider`);
  }
  if (!config.clientSecret) {
    throw new Error(`clientSecret is required for ${providerName} provider`);
  }
  if (!config.strategy) {
    throw new Error(`strategy is required for ${providerName} provider`);
  }
};

/**
 * Normalizes and resolves callback URL for an OAuth2 provider.
 */
const normalizeCallbackURL = (
  callbackURL: string | undefined,
  baseURL: string,
  prefix: string,
  providerName: string
): string => {
  if (!callbackURL) {
    return `${baseURL}${prefix}/${providerName}/callback`;
  }
  if (callbackURL.startsWith("http://") || callbackURL.startsWith("https://")) {
    return callbackURL;
  }
  const cleanPath = callbackURL.startsWith("/")
    ? callbackURL
    : `/${callbackURL}`;
  return `${baseURL}${cleanPath}`;
};

/**
 * Configures a single OAuth2 provider and registers it with Passport.
 */
const setupOauth2Provider = (
  providerName: string,
  providerConfig: ProviderConfig,
  config: Config,
  logger: any
) => {
  if (!config.oauth2) {
    throw new Error("OAuth2 configuration is missing");
  }

  logger.info(`Setting up OAuth 2.0 provider for ${providerName}`);

  const basePrefix = config.oauth2.prefix || "/auth";
  const baseURL = config.oauth2.baseURL ?? "";

  const callbackURL = normalizeCallbackURL(
    providerConfig.callbackURL,
    baseURL,
    basePrefix,
    providerName
  );

  const strategyConfig: any = {
    clientID: providerConfig.clientID,
    clientSecret: providerConfig.clientSecret,
    callbackURL,
  };

  if (!providerConfig.customConfig?.scope) {
    strategyConfig.scope = providerConfig.scope || ["profile", "email"];
  }

  if (providerConfig.customConfig) {
    Object.assign(strategyConfig, providerConfig.customConfig);
  }

  const verifyCallback =
    providerConfig.customVerifyCallback ||
    createVerifyCallback(providerName, providerConfig, config, logger);

  try {
    const StrategyClass = providerConfig.strategy;
    const strategy = new StrategyClass(strategyConfig, verifyCallback);
    passport.use(providerName, strategy);

    logger.info(`${providerName} OAuth 2.0 provider setup complete`, {
      callbackURL,
      scope: strategyConfig.scope,
    });
  } catch (error: any) {
    logger.error(`Failed to instantiate strategy for ${providerName}`, {
      error: error.message,
      strategyConfig: {
        ...strategyConfig,
        clientSecret: "[REDACTED]",
      },
    });
    throw error;
  }
};

/**
 * Creates a verify callback function for Passport OAuth2 strategy.
 * Loads existing user and prepares callback info for the onSuccess handler.
 */
const createVerifyCallback = (
  providerName: string,
  providerConfig: ProviderConfig,
  config: Config,
  logger: any
) => {
  return async (
    accessToken: string,
    refreshToken: string,
    profile: any,
    done: (error: any, user?: any, info?: any) => void
  ) => {
    try {
      logger.info(`${providerName} OAuth 2.0 strategy triggered`);

      const emailPath =
        providerConfig.profileMapping?.email || "emails[0].value";
      const idPath = providerConfig.profileMapping?.id || "id";
      const namePath = providerConfig.profileMapping?.name || "displayName";

      const email = getNestedValue(profile, emailPath);
      const providerId = getNestedValue(profile, idPath) || profile.id;
      const name = getNestedValue(profile, namePath);
      const login = getNestedValue(profile, "login");

      const username =
        email || login || `${providerName}:${providerId || Date.now()}`;

      if (!email) {
        logger.warn(`Email not found in ${providerName} profile`, {
          profile: JSON.stringify(profile, null, 2),
        });
        return done(null, false, {
          message: `Email not provided by ${providerName}. Please ensure the correct scopes are configured.`,
        });
      }

      logger.info(
        `Attempting to load user with email: ${email} from ${providerName}`
      );

      const existingUser = await config.userService.loadUser(email);

      // Prepare the OAuth profile
      const oauthProfile: OAuthUserProfile = {
        provider: providerName,
        providerId: providerId?.toString() || "",
        username,
        email,
        login: login || "",
        attributes: profile._json || profile,
      };

      // Prepare callback info to pass to routes
      const callbackInfo: OAuth2CallbackInfo = {
        provider: providerName,
        profile: oauthProfile,
        accessToken,
        refreshToken,
        existingUser,
      };

      // Pass the callback info through to the route handler
      return done(null, callbackInfo);
    } catch (err: any) {
      logger.error(`Error in ${providerName} OAuth 2.0 strategy`, {
        error: err.message,
        stack: err.stack,
      });
      return done(err, null);
    }
  };
};

/**
 * Retrieves a nested value from an object using a dot-path string.
 */
const getNestedValue = (obj: any, path: string): any => {
  if (!path) return undefined;
  try {
    const normalizedPath = path.replace(/\[(\d+)\]/g, ".$1");
    return normalizedPath.split(".").reduce((current, key) => {
      if (current && typeof current === "object") {
        return current[key];
      }
      return undefined;
    }, obj);
  } catch {
    return undefined;
  }
};
