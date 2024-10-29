const express = require("express");
const passport = require("passport");
const { generateJwt } = require("../utils");
const logger = require("../libs/wintson-logger");

const router = express.Router();

// Session-based login (POST /login/session-based)
router.post(
  "/login/session-based",
  passport.authenticate("local", {
    failureRedirect: "/login/failure",
  }),
  (req, res) => {
    logger.info(
      `User ${req.user.username} successfully logged in with session.  Session ID: ${req.sessionID}`
    );
    res.send(
      `Welcome, ${req.user.username}. You are logged in using session-based auth.`
    );
  }
);

// JWT login (POST /login/passport)
router.post("/login/passport", (req, res, next) => {
  passport.authenticate("local", { session: false }, (err, user, info) => {
    if (err) {
        logger.error('Login error:', err);
        return res.status(500).json({ message: 'Internal server error' });
      }
      if (!user) {
        logger.warn('JWT login failed: Incorrect username or password');
        return res.status(401).json({ message: 'Authentication failed' });
      }
    const token = generateJwt(user);
    logger.info(`User ${user.username} successfully logged in with JWT`);
    return res.json({ message: "JWT login successful", token });
  })(req, res, next);
});

// google login ()
router.get('/auth/google',
    passport.authenticate('google', { scope: ['profile'] }));
  
  router.get('/auth/google/callback', 
    passport.authenticate('google', { failureRedirect: '/login/failure' }),
    function(req, res) {
      // Successful authentication, redirect home.
      res.send({message: 'successfully login through google auth'});
    });

// Protected route for session-based auth (GET /dashboard/session)
router.get("/dashboard/session", isAuthenticated, (req, res) => {
    logger.info(`User ${req.user.username} accessed session-protected route with Session ID: ${req.sessionID}`);
  res.send(`Welcome to your session-based dashboard, ${req.user.username}! `);
});

// Protected route for JWT auth (GET /dashboard/jwt)
router.get(
  "/dashboard/jwt",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    logger.info(`User ${req.user.username} accessed JWT-protected route`);

    res.send(`Welcome to your JWT-protected dashboard, ${req.user.username}!`);
  }
);

// Logout for session-based auth
router.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) return next(err);
    res.send("Logged out successfully");
  });
});

// Middleware to check session-based authentication
function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  logger.warn('Unauthorized access attempt to session-protected route');
  res.redirect("/login/failure");
}

// Route to handle login failure
router.get("/login/failure", (req, res) => {
  res.status(401).send("Login failed. Please check your credentials.");
});

module.exports = router;
