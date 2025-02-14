# AuthCore: Unified Authentication Middleware for Express.js and Nest.js

AuthCore is a lightweight authentication middleware designed to streamline the process of implementing JWT, session-based, and Google OAuth2 authentication in your Express.js and Nest.js applications. With AuthCore, you can easily integrate and manage multiple authentication strategies through a single, unified configuration.

## Features

- **JWT Authentication**: Supports access and refresh tokens with customizable expiry times.
- **Session-based Authentication**: Includes session management with customizable settings.
- **Google OAuth2**: Simplifies Google login integration with minimal setup.
- **Customizable Verification Logic**: Supports a pluggable `password_checker` and `load_user` service for user-specific logic.
- **Single API Endpoint**: Consolidates all authentication strategies into a single verification API.

## Installation

```bash
npm install @flycatch/auth-core
```

## Getting Started

Here’s a quick example of how to use AuthCore in an Express.js application.

### Basic Usage

```javascript
const express = require("express");
const AuthCore = require("@flycatch/auth-core");
const bcrypt = require("bcrypt");

const app = express();
const auth = new AuthCore();

// Configure AuthCore
app.use(
  auth.config({
    jwt: {
      enabled: true,
      secret: "jwt-secret",
      expiresIn: "8h",
      refresh: true,
      prefix: "/auth/jwt",
    },
    session: {
      enabled: true,
      secret: "session-secret",
      resave: false,
      saveUninitialized: true,
      cookie: {
        secure: false,
        maxAge: 24 * 60 * 60 * 1000, // 1 day
      },
    },
    google: {
      enabled: false,
      clientID: "GOOGLE_CLIENT_ID",
      clientSecret: "GOOGLE_CLIENT_SECRET",
      callbackURL: "/auth/google/callback",
      secret: "google-secret",
    },
    user_service: {
      load_user: async (email) => {
        // Implement user lookup logic here
        return { id: 1, email: "example@example.com", name: "John Doe" };
      },
    },
    password_checker: async (inputPassword, storedPassword) => {
      // Implement custom password verification logic here

      return await bcrypt.compare(inputPassword, storedPassword);
    },
  })
);

// Protected Route
app.get("/user", auth.verify(), (req, res) => {
  res.json({ user: req.user });
});

app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});
```

## Configuration Options

### JWT Configuration

```javascript
jwt: {
    enabled: true,
    secret: "your-jwt-secret",
    expiresIn: "8h", // Expiry time for JWT
    refreshToken: true, // Enable refresh tokens
    prefix: "/auth/jwt", // Prefix for JWT-related routes
}
```

### Session Configuration

```javascript
session: {
    enabled: true,
    secret: "your-session-secret",
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: false, // Use true for HTTPS
        maxAge: 24 * 60 * 60 * 1000, // 1 day
    },
}
```

### Google OAuth2 Configuration

```javascript
google: {
    enabled: true,
    clientID: 'GOOGLE_CLIENT_ID',
    clientSecret: 'GOOGLE_CLIENT_SECRET',
    callbackURL: "/auth/google/callback",
    secret: "google-secret", // Internal secret for additional security
}
```

### User Service

```javascript
user_service: {
    load_user: async (email) => {
        // Custom logic to load a user by email
    },
}
```

### Password Checker

```javascript
password_checker: async (inputPassword, storedPassword) => {
  // Custom logic to verify passwords
};
```

## API

### `auth.config(config: Config): Router`

Initializes AuthCore with the provided configuration. Returns an Express router that should be mounted in your app.

### `auth.verify(): Middleware`

Middleware to verify user authentication based on the enabled strategy (JWT, session, or Google OAuth).

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your improvements.

## License

This project is licensed under the GPL-3.0 License.

---
