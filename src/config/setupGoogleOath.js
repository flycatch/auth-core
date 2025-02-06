const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const logger = require("../lib/wintson.logger")

// Function to set up Google OAuth
module.exports = (config) => {
    passport.use(
      new GoogleStrategy(
        {
          clientID: config.google.clientID,
          clientSecret: config.google.clientSecret,
          callbackURL: config.google.callbackURL,
        },
        async (accessToken, refreshToken, profile, done) => {
          try {
            logger.info("Google OAuth strategy triggered");
  
            const email = profile.emails[0].value;
            logger.info(`Processing Google OAuth `);
  
            const user = await config.user_service.load_user(email);
            if (!user) {
              logger.warn(`User not found for email: ${email}`);
              return done(null, false, { message: "User not authorized" });
            }
  
            logger.info(`User successfully authenticated`);
            return done(null, user);
          } catch (err) {
            logger.error("Error in Google OAuth strategy", { error: err.message });
            return done(err, null);
          }
        }
      )
    );
  
    passport.serializeUser((user, done) => {
      logger.info(`Serializing user`);
      done(null, user);
    });
  
    passport.deserializeUser((user, done) => {
      logger.info(`Deserializing user`);
      done(null, user);
    });
  }