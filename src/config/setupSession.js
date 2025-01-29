const session = require("express-session");


// Function to set up session configuration
export function setupSession(router, config) {
  const { secret, resave, saveUninitialized, cookie } = config.session;

  router.use(
    session({
      secret: secret || "Default_secret",
      resave: resave || false,
      saveUninitialized: saveUninitialized || true,
      cookie: {
        secure: cookie.secure || false,
        maxAge: cookie.maxAge || 24 * 60 * 60 * 1000, // 1 day
      },
    })
  );
}