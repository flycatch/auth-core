/* eslint-disable @typescript-eslint/no-explicit-any */
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Strategy as FacebookStrategy } from "passport-facebook";
import { Strategy as GitHubStrategy } from "passport-github2";
// import { Strategy as TwitterStrategy } from "passport-twitter";
import { Config } from "../interfaces/config.interface";
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

  // Add other providers similarly...
};

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
