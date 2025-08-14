/* eslint-disable @typescript-eslint/no-explicit-any */
import { Config } from "../interfaces/config.interface";
import passport, { Profile } from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import createLogger from "../lib/wintson.logger";

// Function to set up Google OAuth
export default (config: Config): void => {
  if (!config.google) {
    throw new Error("google auth not configured");
  }
  const logger = createLogger(config);

  passport.use(
    new GoogleStrategy(
      {
        clientID: config.google.clientID,
        clientSecret: config.google.clientSecret,
        callbackURL: `${
          config.google.prefix ? config.google.prefix : "/auth/google"
        }/callback`,
      },
      async (
        accessToken: string,
        refreshToken: string,
        profile: Profile,
        done: (error: any, user?: any, info?: any) => void
      ) => {
        try {
          logger.info("Google OAuth strategy triggered");

          const email = profile.emails?.[0]?.value;
          logger.info("Processing Google OAuth");

          if (!email) {
            logger.warn("Email not found in Google profile");
            return done(null, false, {
              message: "Email not provided by Google",
            });
          }

          const user = await config.userService.loadUser(email);
          if (!user) {
            logger.warn(`User not found for email: ${email}`);
            return done(null, false, { message: "User not authorized" });
          }

          logger.info("User successfully authenticated");
          return done(null, user);
        } catch (err: any) {
          logger.error("Error in Google OAuth strategy", {
            error: err.message,
          });
          return done(err, null);
        }
      }
    )
  );

  passport.serializeUser((user: any, done) => {
    logger.info("Serializing user");
    done(null, user);
  });

  passport.deserializeUser((user: any, done) => {
    logger.info("Deserializing user");
    done(null, user);
  });
};
