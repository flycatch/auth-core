const passport = require('passport');

var JwtStrategy = require('passport-jwt').Strategy,
    ExtractJwt = require('passport-jwt').ExtractJwt;
var opts = {}
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
opts.secretOrKey = 'jwtsecret';


const users = [
    { username: 'admin', password: 1234, id: 1 },
    { username: 'ramu', password: 1234, id: 12 },
    { username: 'anu', password: 1234, id: 123 }
  ];

// Configure the JWT strategy
passport.use(
    new JwtStrategy(opts, (jwt_payload, done) => {
        console.log('hel')
        // Find the user from the array based on id (jwt_payload.sub is often used, but this depends on your payload)
        const user = users.find(u => u.id === jwt_payload.id);
        console.log(user)
        if (user) {
            return done(null, user); // User found, pass user to the next middleware
        } else {
            return done(null, false); // No user found, authentication fails
        }
    })
);


















// const express = require('express');
// const passport = require('passport');
// const jwt = require('jsonwebtoken');
// // const bcrypt = require('bcryptjs');
// const LocalStrategy = require('passport-local').Strategy;

// const users = [
//     { username: 'admin', password: 1234 },
//     { username: 'ramu', password: 1234 },
//     { username: 'anu', password: 1234 }
// ]; 

// // Passport configuration
// passport.use(new LocalStrategy((username, password, done) => {
//     const user = users.find(u => u.username === username && u.password === password);
//     if (!user) {
//         return done(null, false, { message: 'Incorrect username or password' });
//     }
//     console.log('hs');
//     return done(null, user);

//     // bcrypt.compare(password, user.password, (err, isMatch) => {
//     //     if (err) return done(err);
//     //     if (!isMatch) return done(null, false, { message: 'Incorrect password.' });
//     //     return done(null, user);
//     // });
// }));


// // const passport = require('passport');
// // const { ExtractJwt, Strategy: JwtStrategy } = require('passport-jwt');
// // const users = require('../models/users');

// // // JWT secret key
// // const JWT_SECRET = 'your_jwt_secret_key';

// // // Passport JWT strategy configuration
// // const opts = {
// //     jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
// //     secretOrKey: JWT_SECRET,
// // };

// // // Define the JWT strategy
// // passport.use(new JwtStrategy(opts, (jwtPayload, done) => {
// //     const user = users.find(user => user.username === jwtPayload.username);
// //     if (user) {
// //         return done(null, user);
// //     } else {
// //         return done(null, false);
// //     }
// // }));
