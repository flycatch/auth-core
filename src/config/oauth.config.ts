import { Config } from "../interfaces/config.interface";
import createLogger from "../lib/wintson.logger";
import { setupGoogleStrategy } from "./google.config";
import { setupGithubStrategy } from "./github.config";
import { setupTwitterStrategy } from "./twitter.config";
import { setupCustomProviders } from "./custom-oauth.config";
import { setupFacebookStrategy } from "./facebook.config";

export default (config: Config): void => {
  if (!config.oauth?.enabled) return;

  const logger = createLogger(config);

  // Google Strategy
  setupGoogleStrategy(config, logger);

  // Facebook Strategy
  setupFacebookStrategy(config, logger);

  // Github Strategy
  setupGithubStrategy(config, logger);

  // Twitter Strategy
  setupTwitterStrategy(config, logger);

  // Custom Provider Strategy
  setupCustomProviders(config, logger);
};
