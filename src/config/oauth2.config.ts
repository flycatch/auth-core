/* eslint-disable @typescript-eslint/no-explicit-any */
import passport from "passport";
import { Config, CustomProviderConfig } from "../interfaces/config.interface";

export default (config: Config, logger: any) => {
  if (!config.oauth2?.enabled || !config.oauth2?.providers) {
    logger.warn("OAuth2 is not enabled or no providers configured");
    return;
  }

  // Validate base configuration
  if (!config.oauth2.baseURL) {
    throw new Error("OAuth2 baseURL is required when OAuth2 is enabled");
  }

  Object.entries(config.oauth2.providers).forEach(
    ([providerName, providerConfig]) => {
      try {
        if (!providerConfig) {
          throw new Error(`Provider config missing for ${providerName}`);
        }

        // Validate required fields
        validateProviderConfig(providerName, providerConfig);

        // Setup the provider
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

// Normalize callback URL to absolute URL
const normalizeCallbackURL = (
  callbackURL: string | undefined,
  baseURL: string,
  prefix: string,
  providerName: string
): string => {
  // If no callback URL provided, generate default
  if (!callbackURL) {
    return `${baseURL}${prefix}/${providerName}/callback`;
  }

  // If already absolute URL, return as-is
  if (callbackURL.startsWith("http://") || callbackURL.startsWith("https://")) {
    return callbackURL;
  }

  // Relative URL - make it absolute
  const cleanPath = callbackURL.startsWith("/") ? callbackURL : `/${callbackURL}`;
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
    createCustomVerifyCallback(providerName, providerConfig, config, logger);

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

// Create custom verify callback for OAuth 2.0
const createCustomVerifyCallback = (
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

      // Extract email using custom mapping or default
      const emailPath = providerConfig.profileMapping?.email || "emails[0].value";
      const email = getNestedValue(profile, emailPath);

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
      const user = await config.userService.loadUser(email);

      if (!user) {
        logger.warn(`User not found for email: ${email} from ${providerName}`);
        return done(null, false, { message: "User not authorized" });
      }

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

// Utility function to get nested values from objects
const getNestedValue = (obj: any, path: string): any => {
  if (!path) return undefined;

  try {
    // Handle array notation like 'emails[0].value'
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
