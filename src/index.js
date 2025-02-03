const jsonWebToken = require("jsonwebtoken");
const express = require("express");
const session = require("express-session");
const logger = require("./lib/wintson.logger");
const jwtRoutes = require("./routes/jwt");
const sessionRoutes = require("./routes/session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const setupGoogleRoutes = require("./routes/setup-google-oath");
const  setupSession  = require("./config/setupSession");
const  setupGoogleOath  = require("./config/setupGoogleOath");
const  jwtMiddleware  = require("./middlewares/jwtMiddleware");
const  sessionMiddleware  = require("./middlewares/sessionMiddleware");
const  googleAuthMiddleware  = require("./middlewares/googleAuthMiddleware");

// Configuration storage
let configurations = {};

// Function to initialize configurations and set up routes
function config(config) {
  configurations = config;
  const router = express.Router();

  // Set up routes if JWT is enabled
  if (config.jwt && config.jwt.enabled) {
    jwtRoutes(router, config);
  }

  // Set up routes if session is enabled
  if (config.session && config.session.enabled) {
    setupSession(router, config);
    sessionRoutes(router, config);
  }

  // Set up routes if Google OAuth is enabled
  if (config.google && config.google.enabled) {
    setupGoogleOath(config);
    setupGoogleRoutes(router, config);
  }

  return router;
}

// // Function to set up session configuration
// function setupSession(router, config) {
//   const { secret, resave, saveUninitialized, cookie } = config.session;

//   router.use(
//     session({
//       secret: secret || "Default_secret",
//       resave: resave || false,
//       saveUninitialized: saveUninitialized || true,
//       cookie: {
//         secure: cookie.secure || false,
//         maxAge: cookie.maxAge || 24 * 60 * 60 * 1000, // 1 day
//       },
//     })
//   );
// }

// // Function to set up Google OAuth
// function setupGoogleOath(config) {
//   passport.use(
//     new GoogleStrategy(
//       {
//         clientID: config.google.clientID,
//         clientSecret: config.google.clientSecret,
//         callbackURL: config.google.callbackURL,
//       },
//       async (accessToken, refreshToken, profile, done) => {
//         try {
//           logger.info("Google OAuth strategy triggered");

//           const email = profile.emails[0].value;
//           logger.info(`Processing Google OAuth `);

//           const user = await config.user_service.load_user(email);
//           if (!user) {
//             logger.warn(`User not found for email: ${email}`);
//             return done(null, false, { message: "User not authorized" });
//           }

//           logger.info(`User successfully authenticated`);
//           return done(null, user);
//         } catch (err) {
//           logger.error("Error in Google OAuth strategy", { error: err.message });
//           return done(err, null);
//         }
//       }
//     )
//   );

//   passport.serializeUser((user, done) => {
//     logger.info(`Serializing user`);
//     done(null, user);
//   });

//   passport.deserializeUser((user, done) => {
//     logger.info(`Deserializing user`);
//     done(null, user);
//   });
// }

// Middleware function for verifying authentication
function verify() {
  return (req, res, next) => {
    const { jwt, session, google } = configurations;


    if (jwt && jwt.enabled) {
      return jwtMiddleware(config)(req, res, next);
      // const authHeader = req.headers["authorization"];
      // if (authHeader) {
      //   logger.info("JWT identified, verifying");
      //   const token = authHeader.split(" ")[1];

      //   jsonWebToken.verify(token, jwt.secret || 'jwt_secret@auth', (err, user) => {
      //     if (err) {
      //       logger.warn("Invalid or expired token", { error: err.message });
      //       return res.status(403).json({ error: "Token is invalid or expired" });
      //     }

      //     logger.info(`JWT verified successfully for username`);
      //     req.user = user;
      //     return next();
      //   });
      // } else {
      //   logger.warn("Unauthorized access attempt");
      //   return res.status(401).json({ error: "Unauthorized" });
      // }
    } else if (session && session.enabled) {
      return sessionMiddleware(config)(req, res, next);
      // if (req.session && req.session.user) {
      //   logger.info(`Session verified for username`);
      //   req.user = req.session.user;
      //   return next();
      // } else {
      //   logger.warn("Unauthorized access attempt");
      //   return res.status(401).json({ error: "Unauthorized" });
      // }
    } else if (google && google.enabled) {
      return googleAuthMiddleware(config)(req, res, next);
      // const authHeader = req.headers["authorization"];
      // if (authHeader) {
      //   logger.info("JWT header found in Google OAuth, verifying");
      //   const token = authHeader.split(" ")[1];

      //   jsonWebToken.verify(token, google.secret, (err, user) => {
      //     if (err) {
      //       logger.warn("Invalid or expired token", { error: err.message });
      //       return res.status(403).json({ error: "Token is invalid or expired" });
      //     }

      //     logger.info(`JWT verified successfully for Google OAuth`);
      //     req.user = user;
      //     next();
      //   });
      // } else {
      //   return res.status(401).json({ error: "Unauthorized" });
      // }
    } else {
      logger.warn("Authentication is not configured");
      return res.status(500).json({ error: "Authentication not configured" });
    }
  };
}

module.exports = { config, verify };









// const jsonWebToken = require("jsonwebtoken");
// const express = require("express");
// const session = require("express-session");
// const logger = require("./lib/wintson.logger");
// const jwtRoutes = require("./routes/jwt");
// const sessionRoutes = require("./routes/session");
// const passport = require('passport');
// const GoogleStrategy = require('passport-google-oauth20').Strategy;
// const setupGoogleRoutes = require("./routes/setup-google-oath");

// class AuthCore {
//   constructor() {
//     this.configurations = {};
//     this.router = express.Router();
//   }

//   config(config) {
//     this.configurations = config;

//     // Automatically set up routes if JWT is enabled
//     if (config.jwt && config.jwt.enabled) {
//       jwtRoutes(this.router, config);
//     }
//     // Automatically set up routes if session is enabled
//     if (config.session && config.session.enabled) {
//       this.setupSession(config);
//       sessionRoutes(this.router, config);
//     }
//     // Automatically set up routes if google is enabled
//     if (config.google && config.google.enabled) {
//       this.setupGoogleOath( config);
//       setupGoogleRoutes(this.router, config);

//     }
//     return this.router;
//   }

//   setupSession(config) {
//     const { secret, resave, saveUninitialized, cookie } = config.session;

//     this.router.use(
//       session({
//         secret: secret || "Default_secret",
//         resave: resave || false,
//         saveUninitialized: saveUninitialized || true,
//         cookie: {
//           secure: cookie.secure || false,
//           maxAge: cookie.maxAge || 24 * 60 * 60 * 1000, // 1 day
//         },
//       })
//     );
//   }



// setupGoogleOath(config) {
//   passport.use(
//     new GoogleStrategy(
//       {
//         clientID: config.google.clientID,
//         clientSecret: config.google.clientSecret,
//         callbackURL: config.google.callbackURL,
//       },
//       async (accessToken, refreshToken, profile, done) => {
//         try {
//           logger.info("Google OAuth strategy triggered");
//           logger.debug(`Access Token: ${accessToken}`);
//           logger.debug(`Refresh Token: ${refreshToken}`);
//           logger.debug(`Google Profile: ${JSON.stringify(profile)}`);
  
//           const email = profile.emails[0].value;
//           logger.info(`Processing Google OAuth for email: ${email}`);
  
//           // Check for user existence in DB
//           const user = await config.user_service.load_user(email);
//           if (!user) {
//             logger.warn(`User not found for email: ${email}`);
//             return done(null, false, { message: "User not authorized" });
//           }
  
//           logger.info(`User successfully authenticated: ${user.username}`);
//           return done(null, user);
//         } catch (err) {
//           logger.error("Error in Google OAuth strategy", { error: err.message });
//           return done(err, null);
//         }
//       }
//     )
//   );

//   // Serialize and deserialize user
//   passport.serializeUser((user, done) => {
//     logger.info(`Serializing user: ${user.username}`);
//     done(null, user);
//   });

//   passport.deserializeUser((user, done) => {
//     logger.info(`Deserializing user: ${user.username}`);
//     done(null, user);
//   });
// }



// verify() {
//     return (req, res, next) => {
//       const { jwt, session, google } = this.configurations;
  
//       // Check if JWT and Session are both enabled
//       if (jwt && jwt.enabled && session && session.enabled) {
//         const authHeader = req.headers["authorization"];
  
//         // If JWT token is provided, prioritize JWT authentication
//         if (authHeader) {
//           logger.info("JWT header found, verifying...");
//           const token = authHeader.split(" ")[1];
  
//           jsonWebToken.verify(token, jwt.secret, (err, user) => {
//             if (err) {
//               logger.warn("Invalid or expired token", { error: err.message });
//               return res.status(403).json({ error: "Token is invalid or expired" });
//             }
  
//             logger.info(`JWT verified successfully for username: ${user.username}`);
//             req.user = user;
//             return next();
//           });
//         } else if (req.session && req.session.user) {
//           // Fallback to session verification if no JWT token is found
//           logger.info(`Session verified for username: ${req.session.user.username}`);
//           req.user = req.session.user;
//           return next();
//         } else {
//           // If neither JWT nor session is valid
//           logger.warn("Unauthorized access attempt");
//           return res.status(401).json({ error: "Unauthorized" });
//         }
//       } else if (jwt && jwt.enabled) {
//         // If only JWT is enabled
//         const authHeader = req.headers["authorization"];
//         if (authHeader) {
//           logger.info("JWT only, verifying...");
//           const token = authHeader.split(" ")[1];
  
//           jsonWebToken.verify(token, jwt.secret, (err, user) => {
//             if (err) {
//               logger.warn("Invalid or expired token", { error: err.message });
//               return res.status(403).json({ error: "Token is invalid or expired" });
//             }
  
//             logger.info(`JWT verified successfully for username: ${user.username}`);
//             req.user = user;
//             return next();
//           });
//         } else {
//           logger.warn("Unauthorized access attempt");
//           return res.status(401).json({ error: "Unauthorized" });
//         }
//       } else if (session && session.enabled) {
//         // If only session is enabled
//         if (req.session && req.session.user) {
//           logger.info(`Session verified for username: ${req.session.user.username}`);
//           req.user = req.session.user;
//           return next();
//         } else {
//           logger.warn("Unauthorized access attempt");
//           return res.status(401).json({ error: "Unauthorized" });
//         }
//       }
//       else if(google && google.enabled) {
//         const authHeader = req.headers["authorization"];
//         if (authHeader) {
//           logger.info("JWT header found in google oath, verifying...");

//           const token = authHeader.split(' ')[1];
   
//           jsonWebToken.verify(token, google.secret, (err, user) => {
//             if (err) {
//               logger.warn("Invalid or expired token", { error: err.message });
//               return res.status(403).json({ error: 'Token is invalid or expired' });
//             }
//             logger.info(`JWT verified successfully as google oath for username: ${user.username}`);

//             req.user = user;
//             next();
//           });
//         } else {
//           return res.status(401).json({ error: 'Unauthorized' });
//         }

//       }
//       else {
//         // If neither JWT or google nor session is enabled
//         logger.warn("Authentication is not configured");
//         return res.status(500).json({ error: "Authentication not configured" });
//       }
//     };
//   }
  
// }
// const auth = new AuthCore();
// // module.exports.default = auth; // Add a default export
// // // export default new AuthCore();

// // // module.exports = new AuthCore();



// module.exports = auth;
// module.exports.AuthCore = AuthCore; // Add class for NestJS DI compatibility
// module.exports.default = auth;