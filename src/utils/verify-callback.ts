/* eslint-disable @typescript-eslint/no-explicit-any */
import { Config, CustomProviderConfig } from "../interfaces/config.interface";

// Standard verify callback for OAuth 2.0 providers
export const createVerifyCallback = (
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
export const createTwitterVerifyCallback = (
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

// Create custom verify callback for OAuth 2.0
export const createCustomVerifyCallback = (
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
