import passport from "passport";
import { Strategy as TwitterStrategy } from "passport-twitter";
import { Config } from "../interfaces/config.interface";
import { createTwitterVerifyCallback } from "../utils/verify-callback";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const setupTwitterStrategy = (config: Config, logger: any): void => {
  if (!config.oauth?.providers.twitter) return;

  const twitterCallbackURL =
    config.oauth.providers.twitter.callbackURL ||
    `${config.oauth.baseURL}${config.oauth.prefix}/twitter/callback`;

  passport.use(
    new TwitterStrategy(
      {
        consumerKey: config.oauth.providers.twitter.clientID,
        consumerSecret: config.oauth.providers.twitter.clientSecret,
        callbackURL: twitterCallbackURL,
        includeEmail: true,
        userProfileURL:
          "https://api.twitter.com/1.1/account/verify_credentials.json?include_email=true",
      },
      createTwitterVerifyCallback("twitter", config, logger)
    )
  );
};
