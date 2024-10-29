const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const bcrypt = require('bcryptjs');
const users = require('../mock-data/users');
const { jwtSecret } = require('../utils');
const logger = require('../libs/wintson-logger');

// Session-based strategy
passport.use('local', new LocalStrategy((username, password, done) => {

  const user = users.find(u => u.username === username);
  if (!user) {
    logger.warn(`Login attempt failed: User ${username} not found`);
    return done(null, false, { message: 'Incorrect username.' });
  }

  bcrypt.compare(password, user.password, (err, isMatch) => {
    if (err) {
        logger.error('Password comparison error:', err);
        return done(err);
      }
          if (isMatch) {
            logger.info(`User ${username} authenticated successfully`);

      return done(null, user);
    } else {
        logger.warn(`Login attempt failed: Incorrect password for user ${username}`);

      return done(null, false, { message: 'Incorrect password.' });
    }
  });
}));

// JWT strategy
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: jwtSecret,
};
passport.use(new JwtStrategy(jwtOptions, (jwtPayload, done) => {
  const user = users.find(u => u.id === jwtPayload.id);
  if (user) {
    logger.info(`JWT token validated for user ${user.username}`);

    return done(null, user);
  } else {
    logger.warn('JWT token validation failed');

    return done(null, false);
  }
}));

// Serialize user (for session-based)
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  const user = users.find(u => u.id === id);
  if (user) {
    logger.info(`User ${user.username} deserialized from session`);
  
  done(null, user);
  }
  else {
    logger.warn('User not found during session deserialization');
    done(new Error('User not found'));
  }
});
