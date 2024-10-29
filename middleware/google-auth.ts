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
  