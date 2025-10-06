/* eslint-disable @typescript-eslint/no-explicit-any */
import passport from "passport";
import { Config, CustomProviderConfig } from "../interfaces/config.interface";
import { createCustomVerifyCallback } from "../utils/verify-callback";

export default (config: Config, logger: any) => {
  if (!config.oauth2?.providers) return;

  Object.entries(config.oauth2.providers).forEach(
    ([providerName, providerConfig]) => {
      try {
        setupOauth2Provider(providerName, providerConfig, config, logger);
      } catch (error) {
        logger.error(
          `Failed to setup ouath 2.0 provider for ${providerName}:`,
          error
        );
      }
    }
  );
};

// Setup individual custom OAuth 2.0 provider
const setupOauth2Provider = (
  providerName: string,
  providerConfig: CustomProviderConfig,
  config: Config,
  logger: any
) => {
  if (!config.oauth2) {
    throw new Error();
  }
  logger.info(`Setting up OAuth 2.0 provider for ${providerName}`);

  // Create strategy configuration
  const strategyConfig = {
    clientID: providerConfig.clientID,
    clientSecret: providerConfig.clientSecret,
    callbackURL:
      providerConfig.callbackURL ||
      `${config.oauth2.prefix || "/auth"}/${providerName}/callback`,
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
  logger.info(`${providerName} OAuth 2.0 provider setup complete`);
};
