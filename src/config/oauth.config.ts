/* eslint-disable @typescript-eslint/no-explicit-any */
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Strategy as FacebookStrategy } from "passport-facebook";
import { Strategy as GitHubStrategy } from "passport-github2";
import { Strategy as TwitterStrategy } from "passport-twitter";
import { Config, CustomProviderConfig } from "../interfaces/config.interface";
import createLogger from "../lib/wintson.logger";

export default (config: Config): void => {
  if (!config.oauth?.enabled) return;

  const logger = createLogger(config);
  const providers = config.oauth.providers;

  // Google Strategy
  if (providers.google) {
    passport.use(
      new GoogleStrategy(
        {
          clientID: providers.google.clientID,
          clientSecret: providers.google.clientSecret,
          callbackURL:
            providers.google.callbackURL ||
            `${config.oauth.prefix || "/auth"}/google/callback`,
          scope: providers.google.scope || ["profile", "email"],
        },
        createVerifyCallback("google", config, logger)
      )
    );
  }

  // Facebook Strategy
  if (providers.facebook) {
    passport.use(
      new FacebookStrategy(
        {
          clientID: providers.facebook.clientID,
          clientSecret: providers.facebook.clientSecret,
          callbackURL:
            providers.facebook.callbackURL ||
            `${config.oauth.prefix || "/auth"}/facebook/callback`,
          scope: providers.facebook.scope || ["email"],
          profileFields: ["id", "emails", "name"],
        },
        createVerifyCallback("facebook", config, logger)
      )
    );
  }

  // Github Strategy
  if (providers.github) {
    passport.use(
      new GitHubStrategy(
        {
          clientID: providers.github.clientID,
          clientSecret: providers.github.clientSecret,
          callbackURL:
            providers.github.callbackURL ||
            `${config.oauth.prefix || "/auth"}/github/callback`,
          scope: providers.github.scope || ["email"],
        },
        createVerifyCallback("github", config, logger)
      )
    );
  }

  // Twitter Strategy
  if (providers.twitter) {
    const twitterCallbackURL =
      providers.twitter.callbackURL ||
      `${config.oauth.baseURL}${config.oauth.prefix}/twitter/callback`;
    logger.info("Twitter OAuth Callback URL:", twitterCallbackURL);
    logger.info(
      "Twitter Consumer Key:",
      providers.twitter.clientID?.substring(0, 10) + "..."
    );

    passport.use(
      new TwitterStrategy(
        {
          consumerKey: providers.twitter.clientID,
          consumerSecret: providers.twitter.clientSecret,
          callbackURL: twitterCallbackURL,
          includeEmail: true,
          userProfileURL:
            "https://api.twitter.com/1.1/account/verify_credentials.json?include_email=true",
        },
        createTwitterVerifyCallback("twitter", config, logger)
      )
    );
  }

  // Custom Provider Strategy
  setupCustomProviders(config, logger);
};

// Standard verify callback for OAuth 2.0 providers
const createVerifyCallback = (
  provider: string,
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
      logger.info(`${provider} OAuth strategy triggered`);

      const email = profile.emails?.[0]?.value;
      if (!email) {
        logger.warn("Email not found in profile");
        return done(null, false, { message: "Email not provided" });
      }

      const user = await config.userService.loadUser(email);
      if (!user) {
        logger.warn(`User not found for email: ${email}`);
        return done(null, false, { message: "User not authorized" });
      }

      logger.info("User successfully authenticated");
      return done(null, user);
    } catch (err: any) {
      logger.error(`Error in ${provider} OAuth strategy`, {
        error: err.message,
      });
      return done(err, null);
    }
  };
};

// Special verify callback for Twitter (OAuth 1.0a has different signature)
const createTwitterVerifyCallback = (
  provider: string,
  config: Config,
  logger: any
) => {
  return async (
    token: string,
    tokenSecret: string,
    profile: any,
    done: (error: any, user?: any, info?: any) => void
  ) => {
    try {
      logger.info(`${provider} OAuth strategy triggered`, {
        profileId: profile.id,
        username: profile.username,
        hasEmails: !!profile.emails,
        emailCount: profile.emails?.length || 0,
      });

      const email = profile.emails?.[0]?.value;
      if (!email) {
        logger.warn(`Email not found in ${provider} profile`, {
          profileId: profile.id,
          username: profile.username,
          profileData: JSON.stringify(profile, null, 2),
        });
        return done(null, false, {
          message:
            "Email not provided by Twitter. Please ensure your Twitter app has email permissions.",
        });
      }

      logger.info(`Attempting to load user with email: ${email}`);
      const user = await config.userService.loadUser(email);
      if (!user) {
        logger.warn(`User not found for email: ${email}`);
        return done(null, false, { message: "User not authorized" });
      }

      logger.info(`User successfully authenticated: ${email}`);
      return done(null, user);
    } catch (err: any) {
      logger.error(`Error in ${provider} OAuth strategy`, {
        error: err.message,
        stack: err.stack,
      });
      return done(err, null);
    }
  };
};

const setupCustomProviders = (config: Config, logger: any) => {
  if (!config.oauth?.customProviders) return;

  Object.entries(config.oauth.customProviders).forEach(
    ([providerName, providerConfig]) => {
      try {
        setupCustomProvider(providerName, providerConfig, config, logger);
      } catch (error) {
        logger.error(`Failed to setup custom provider ${providerName}:`, error);
      }
    }
  );
};

// Setup individual custom OAuth 2.0 provider
const setupCustomProvider = (
  providerName: string,
  providerConfig: CustomProviderConfig,
  config: Config,
  logger: any
) => {
  if (!config.oauth) {
    throw new Error();
  }
  logger.info(`Setting up custom OAuth 2.0 provider: ${providerName}`);

  // Create strategy configuration
  const strategyConfig = {
    clientID: providerConfig.clientID,
    clientSecret: providerConfig.clientSecret,
    callbackURL:
      providerConfig.callbackURL ||
      `${config.oauth.prefix || "/auth"}/${providerName}/callback`,
    scope: providerConfig.scope || ["profile", "email"],
    ...providerConfig.customConfig,
  };

  // Use custom verify callback or create default one
  const verifyCallback =
    providerConfig.customVerifyCallback ||
    createCustomVerifyCallback(providerName, providerConfig, config, logger);

  // Create and register strategy
  const StrategyClass = providerConfig.strategy;
  const strategy = new StrategyClass(strategyConfig, verifyCallback);

  passport.use(providerName, strategy);
  logger.info(`Custom OAuth 2.0 provider ${providerName} setup complete`);
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
      const emailPath =
        providerConfig.profileMapping?.email || "emails[0].value";
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
