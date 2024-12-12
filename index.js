const express = require("express");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const auth = require("./auth-core-npm/index");
require("dotenv").config();

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));

// Mock User Repository
const userRepository = {
  // Store mock users in an array
  users: [
    {
      id: '123',
      username: "exampleUser",
      password: bcrypt.hashSync("password123", 10), // Hash the password synchronously
    },
    
  ],

  // Find user by username
  async find(username) {
    return this.users.find((user) => user.username === username) || null;
  },
};

app.use(
  // Configure auth-core
  auth.config({
    jwt: {
      enabled: true,
      refresh: true,
      jwt_expires: "8h",
      secret: "jwt-secret",
      prefix: "/auth/jwt",
    },
    session: {
      enabled: false,
      secret: "session-secret",
      prefix: "/auth/session",
      resave: false,
      saveUninitialized: true,
      cookie: {
        secure: false,
        maxAge: 24 * 60 * 60 * 1000, // 1 day
      },
    },
    google: {
      enabled: false,
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: '/auth/google/callback',
      secret: 'secret',
    },
    password_checker: async (inputPassword, storedPassword) => {
      return await bcrypt.compare(inputPassword, storedPassword);
    },
    user_service: {
      load_user: async (username) => {
        return await userRepository.find(username);
      },
    },
  })
);

// Protected User Route
app.get("/user", auth.verify(), (req, res) => {
  res.json({ message: "Access granted", user: req.user });
});

app.listen(3004, () => {
  console.log("Server running on http://localhost:3004");
});
