import passport from "passport";
import { Strategy as FacebookStrategy } from "passport-facebook";
import { Config } from "../interfaces/config.interface";
import { createVerifyCallback } from "../utils/verify-callback";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const setupFacebookStrategy = (config: Config, logger: any): void => {
  if (!config.oauth?.providers.facebook) return;

  passport.use(
    new FacebookStrategy(
      {
        clientID: config.oauth.providers.facebook.clientID,
        clientSecret: config.oauth.providers.facebook.clientSecret,
        callbackURL:
          config.oauth.providers.facebook.callbackURL ||
          `${config.oauth.prefix || "/auth"}/facebook/callback`,
        scope: config.oauth.providers.facebook.scope || ["email"],
        profileFields: ["id", "emails", "name"],
      },
      createVerifyCallback("facebook", config, logger)
    )
  );
};
