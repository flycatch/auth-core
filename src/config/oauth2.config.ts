/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/no-explicit-any */
import passport from "passport";
import { Config, CustomProviderConfig } from "../interfaces/config.interface";
import {
  User,
  OAuthUserProfile,
  UserProvisionResult,
} from "../interfaces/user.interface";

export default (config: Config, logger: any) => {
  if (!config.oauth2?.enabled || !config.oauth2?.providers) {
    logger.warn("OAuth2 is not enabled or no providers configured");
    return;
  }

  // Validate required configuration
  if (!config.oauth2.successRedirect) {
    throw new Error("OAuth2 successRedirect is required");
  }
  if (!config.oauth2.failureRedirect) {
    throw new Error("OAuth2 failureRedirect is required");
  }
  if (config.oauth2.autoProvision && !config.userService.createUser) {
    throw new Error(
      "UserService.createUser is required when autoProvision is enabled"
    );
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

// Validate provider configuration
const validateProviderConfig = (
  providerName: string,
  config: CustomProviderConfig
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

// Normalize callback URL
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

// Setup individual custom OAuth 2.0 provider
const setupOauth2Provider = (
  providerName: string,
  providerConfig: CustomProviderConfig,
  config: Config,
  logger: any
) => {
  if (!config.oauth2) {
    throw new Error("OAuth2 configuration is missing");
  }

  logger.info(`Setting up OAuth 2.0 provider for ${providerName}`);

  const basePrefix = config.oauth2.prefix || "/auth";
  const baseURL = config.oauth2.baseURL ?? "";

  // Normalize callback URL to absolute URL
  const callbackURL = normalizeCallbackURL(
    providerConfig.callbackURL,
    baseURL,
    basePrefix,
    providerName
  );

  // Create base strategy configuration
  const strategyConfig: any = {
    clientID: providerConfig.clientID,
    clientSecret: providerConfig.clientSecret,
    callbackURL,
  };

  // Add scope if not in customConfig
  if (!providerConfig.customConfig?.scope) {
    strategyConfig.scope = providerConfig.scope || ["profile", "email"];
  }

  // Merge custom config AFTER base config (allows overrides)
  if (providerConfig.customConfig) {
    Object.assign(strategyConfig, providerConfig.customConfig);
  }

  // Use custom verify callback or create default one
  const verifyCallback =
    providerConfig.customVerifyCallback ||
    createVerifyCallback(providerName, providerConfig, config, logger);

  try {
    // Create and register strategy
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

// verify callback with auto-provisioning
const createVerifyCallback = (
  providerName: string,
  providerConfig: CustomProviderConfig,
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

      // Extract user information using profile mapping or defaults
      const emailPath =
        providerConfig.profileMapping?.email || "emails[0].value";
      const idPath = providerConfig.profileMapping?.id || "id";
      const namePath = providerConfig.profileMapping?.name || "displayName";

      const email = getNestedValue(profile, emailPath);
      const providerId = getNestedValue(profile, idPath) || profile.id;
      const name = getNestedValue(profile, namePath);
      const login = getNestedValue(profile, "login"); // GitHub style

      // Generate username: email > login > provider:providerId
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
      let user = await config.userService.loadUser(email);

      // Auto-provision if user doesn't exist and autoProvision is enabled
      if (!user && config.oauth2?.autoProvision) {
        logger.info(`Auto-provisioning new user for email: ${email}`);

        const userProfile: OAuthUserProfile = {
          provider: providerName,
          providerId: providerId?.toString() || "",
          username,
          email,
          login: login || "",
          attributes: profile._json || profile,
        };

        if (config.userService.createUser) {
          user = await config.userService.createUser(userProfile);

          // Apply default role if user has no grants
          if (
            config.oauth2.defaultRole &&
            (!user.grants || user.grants.length === 0)
          ) {
            user.grants = [config.oauth2.defaultRole];
            logger.info(
              `Assigned default role to new user: ${config.oauth2.defaultRole}`
            );
          }
        } else {
          logger.warn(
            "Auto-provisioning enabled but createUser method not provided"
          );
        }
      }

      if (!user) {
        logger.warn(
          `User not found for email: ${email} from ${providerName} and auto-provisioning disabled`
        );
        return done(null, false, { message: "User not authorized" });
      }

      // Add provider information to user object for later use
      user.provider = providerName;
      user.providerId = providerId;

      logger.info(
        `User successfully authenticated via ${providerName}: ${email}`
      );
      return done(null, user);
    } catch (err: any) {
      logger.error(`Error in ${providerName} OAuth 2.0 strategy`, {
        error: err.message,
        stack: err.stack,
      });
      return done(err, null);
    }
  };
};

// Utility function to get nested values from objects (unchanged)
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
