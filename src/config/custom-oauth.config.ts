/* eslint-disable @typescript-eslint/no-explicit-any */
import passport from "passport";
import { Config, CustomProviderConfig } from "../interfaces/config.interface";
import { createCustomVerifyCallback } from "../utils/verify-callback";

export const setupCustomProviders = (config: Config, logger: any) => {
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
