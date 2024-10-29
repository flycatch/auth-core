const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const bcrypt = require('bcryptjs');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const users = require('../mock-data/users');
const { jwtSecret } = require('../utils');
const logger = require('../libs/wintson-logger');
require('dotenv').config();
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



// passport.use(new GoogleStrategy({
//     clientID: process.env.GOOGLE_CLIENT_ID,
//     clientSecret: process.env.GOOGLE_CLIENT_SECRET,
//     callbackURL: "http://localhost:3003/auth/google/callback"
//   },
//   function(accessToken, refreshToken, profile, done) {

//     const user = {
//         googleId: profile.id, // Store Google profile ID
//         username: profile.displayName,
//         email: profile.emails ? profile.emails[0].value : null, // Store email if available
//       };
//       console.log(user);
//    return done(null, profile);
//   }
// ));

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3003/auth/google/callback"
  },
  function(accessToken, refreshToken, profile, done) {
    // Check if the Google user already exists in the `users` array
    let user = users.find(u => u.googleId === profile.id);
  
    if (!user) {
      // If the user does not exist, create a new user object and add it to `users`
      user = {
        id: users.length + 1, // Assign a new unique ID
        googleId: profile.id, // Store Google profile ID
        username: profile.displayName,
        email: profile.emails ? profile.emails[0].value : null, // Store email if available
      };
      users.push(user);
      logger.info(`New Google user ${user.username} added`);
    }
  
    return done(null, user);
  }));
  


// // Serialize user (for session-based)
// passport.serializeUser((user, done) => {
//   done(null, user.id);
// });

// passport.deserializeUser((id, done) => {
//   const user = users.find(u => u.id === id);
//   if (user) {
//     logger.info(`User ${user.username} deserialized from session`);
  
//   done(null, user);
//   }
//   else {
//     logger.warn('User not found during session deserialization');
//     done(new Error('User not found'));
//   }
// });


// passport.serializeUser((user, done) => {
//     done(null, { id: user.id, googleId: user.googleId });
//   });
  
//   passport.deserializeUser((userInfo, done) => {
//     let user;
  
//     if (userInfo.googleId) {
//       // Find Google user by `googleId`
//       user = users.find(u => u.googleId === userInfo.googleId);
//     } else {
//       // Find local user by `id`
//       user = users.find(u => u.id === userInfo.id);
//     }
  
//     if (user) {
//       return done(null, user);
//     } else {
//       logger.warn('User not found during session deserialization');
//       return done(new Error('User not found'));
//     }
//   });
  

passport.serializeUser((user, done) => {
    console.log('serializeUser',user);
    // Save both `id` and `googleId` to identify the user type during deserialization
    done(null, { id: user.id, googleId: user.googleId });
  });
  
  passport.deserializeUser((userInfo, done) => {
    let user;
  
    if (userInfo.googleId) {
      // Google user: find by `googleId`
      user = users.find(u => u.googleId === userInfo.googleId);
    } else {
      // Local user: find by `id`
      user = users.find(u => u.id === userInfo.id);
    }
  
    if (user) {
      return done(null, user);
    } else {
      logger.warn('User not found during session deserialization');
      return done(new Error('User not found'));
    }
  });
  