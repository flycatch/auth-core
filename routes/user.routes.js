const express = require('express');
const passport = require('passport');
const { generateJwt } = require('../utils');

const router = express.Router();

// Session-based login (POST /login/session-based)
router.post('/login/session-based', passport.authenticate('local', {
  failureRedirect: '/login/failure',
}), (req, res) => {
  res.send(`Welcome, ${req.user.username}. You are logged in using session-based auth.`);
});

// JWT login (POST /login/passport)
router.post('/login/passport', (req, res, next) => {
  passport.authenticate('local', { session: false }, (err, user, info) => {
    if (err || !user) {
      return res.status(401).json({ message: 'Login failed' });
    }
    const token = generateJwt(user);
    return res.json({ message: 'JWT login successful', token });
  })(req, res, next);
});

// Protected route for session-based auth (GET /dashboard/session)
router.get('/dashboard/session', isAuthenticated, (req, res) => {
  res.send(`Welcome to your session-based dashboard, ${req.user.username}!`);
});

// Protected route for JWT auth (GET /dashboard/jwt)
router.get('/dashboard/jwt', passport.authenticate('jwt', { session: false }), (req, res) => {
  res.send(`Welcome to your JWT-protected dashboard, ${req.user.username}!`);
});

// Logout for session-based auth
router.get('/logout', (req, res) => {
  req.logout((err) => {
    if (err) return next(err);
    res.send('Logged out successfully');
  });
});

// Middleware to check session-based authentication
function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/login/failure');
}

// Route to handle login failure
router.get('/login/failure', (req, res) => {
  res.status(401).send('Login failed. Please check your credentials.');
});

module.exports = router;
