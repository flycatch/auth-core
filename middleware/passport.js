const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const bcrypt = require('bcryptjs');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const users = require('../mock-data/users');
const { jwtSecret } = require('../utils');
// Session-based strategy
passport.use('local', new LocalStrategy((username, password, done) => {
  const user = users.find(u => u.username === username);
  if (!user) {
    return done(null, false, { message: 'Incorrect username.' });
  }

  bcrypt.compare(password, user.password, (err, isMatch) => {
    if (err) throw err;
    if (isMatch) {
      return done(null, user);
    } else {
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
    return done(null, user);
  } else {
    return done(null, false);
  }
}));


passport.deserializeUser((id, done) => {
  const user = users.find(u => u.id === id);
  done(null, user);
});
