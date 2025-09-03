import passport from "passport";
import { Strategy as GitHubStrategy } from "passport-github2";
import { Config } from "../interfaces/config.interface";
import { createVerifyCallback } from "../utils/verify-callback";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const setupGithubStrategy = (config: Config, logger: any): void => {
  if (!config.oauth?.providers.github) return;

  passport.use(
    new GitHubStrategy(
      {
        clientID: config.oauth.providers.github.clientID,
        clientSecret: config.oauth.providers.github.clientSecret,
        callbackURL:
          config.oauth.providers.github.callbackURL ||
          `${config.oauth.prefix || "/auth"}/github/callback`,
        scope: config.oauth.providers.github.scope || ["email"],
      },
      createVerifyCallback("github", config, logger)
    )
  );
};
