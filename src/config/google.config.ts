import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Config } from "../interfaces/config.interface";
import { createVerifyCallback } from "../utils/verify-callback";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const setupGoogleStrategy = (config: Config, logger: any): void => {
  if (!config.oauth?.providers.google) return;

  passport.use(
    new GoogleStrategy(
      {
        clientID: config.oauth.providers.google.clientID,
        clientSecret: config.oauth.providers.google.clientSecret,
        callbackURL:
          config.oauth.providers.google.callbackURL ||
          `${config.oauth.prefix || "/auth"}/google/callback`,
        scope: config.oauth.providers.google.scope || ["profile", "email"],
      },
      createVerifyCallback("google", config, logger)
    )
  );
};
