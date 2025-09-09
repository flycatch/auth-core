import { Router } from "express";
import { Config } from "../interfaces/config.interface";
import session from "express-session";

// Function to set up session configuration
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
