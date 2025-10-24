import { Router } from "express";
import { Config } from "../interfaces/config.interface";
import session from "express-session";

/**
 * Initializes session configuration and applies it to the provided Express router.
 *
 * This middleware sets up express-session with the configuration defined in `config.session`.
 * Throws an error if session configuration is missing.
 *
 * @param {Router} router - Express router instance to apply session middleware on.
 * @param {Config} config - Application configuration object containing session settings.
 *
 * @throws {Error} If session configuration is not defined in the config object.
 */
export default (router: Router, config: Config) => {
  if (!config.session) {
    throw new Error("Session authentication not configured");
  }

  const { secret, resave, saveUninitialized, cookie } = config.session;

  router.use(
    session({
      secret: secret || "default_session_secret",
      resave: resave || false,
      saveUninitialized: saveUninitialized || true,
      cookie: {
        secure: cookie?.secure || false,
        maxAge: cookie?.maxAge || 24 * 60 * 60 * 1000, // 1 day
      },
    })
  );
};
