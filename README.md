# Auth-Core

Auth-Core is a unified authentication middleware for Node.js applications, supporting JWT-based authentication, session-based authentication, and Google OAuth authentication. This package simplifies authentication management by providing middleware functions that handle authentication flows seamlessly.

## Features

- **JWT Authentication**
- **Session-based Authentication**
- **Google OAuth Authentication**
- **User Service Integration**
- **Customizable Password Checker**
- **Role & Permission-Based Access Control**

## Installation

```sh
npm install @flycatch/auth-core
```

## Usage

### Import and Configure Auth-Core

```javascript
const express = require("express");
const { config, verify } = require("@flycatch/auth-core");
const bcrypt = require("bcrypt");

const app = express();

const userRepository = {
  async find(email) {
    return { id: "123", email, username: "exampleUser", grands: ["read_user"] };
  },
};

app.use(
  config({
    jwt: {
      enabled: true,
      secret: "my_jwt_secret",
      expiresIn: "1h",
      refresh: true,
      prefix: "/auth/jwt",
    },
    session: {
      enabled: false,
      prefix: "/auth/session",
      secret: "my_session_secret",
      resave: false,
      saveUninitialized: true,
      cookie: { secure: false, maxAge: 60000 },
    },
    google: {
      enabled: false,
      clientID: "GOOGLE_CLIENT_ID",
      clientSecret: "GOOGLE_CLIENT_SECRET",
      callbackURL: "/auth/google/callback",
      secret: "google_secret",
    },
    user_service: {
      load_user: async (email) => userRepository.find(email),
    },
    password_checker: async (inputPassword, storedPassword) =>
      bcrypt.compare(inputPassword, storedPassword),
    logs: true,
  })
);

// Protected Route
app.get("/user", verify(), (req, res) => {
  res.json({ message: "Access granted", user: req.user });
});

app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});
```

## Configuration Options Explained

### **JWT Authentication**

```javascript
jwt: {
  enabled: true,
  secret: "my_jwt_secret",
  expiresIn: "1h",
  refresh: true,
  prefix: "/auth/jwt",
},
```

- **enabled**: Enables or disables JWT authentication.
- **secret**: The secret key used to sign JWT tokens.
- **expiresIn**: Defines how long the access token remains valid (e.g., "1h" for 1 hour).
- **refresh**: Enables refresh token support.
- **prefix**: The route prefix for JWT authentication endpoints.

### **Session-Based Authentication**

```javascript
session: {
  enabled: false,
  prefix: "/auth/session",
  secret: "my_session_secret",
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false, maxAge: 60000 },
},
```

- **enabled**: Enables session-based authentication.
- **prefix**: Defines the route prefix for session authentication endpoints.
- **secret**: The session secret key.
- **resave**: Determines if the session should be saved even if it wasn’t modified.
- **saveUninitialized**: Saves uninitialized sessions.
- **cookie**: Configures session cookies:
  - **secure**: Ensures cookies are sent only over HTTPS.
  - **maxAge**: Specifies cookie expiration time in milliseconds.

### **Google OAuth Authentication**

```javascript
google: {
  enabled: false,
  clientID: "GOOGLE_CLIENT_ID",
  clientSecret: "GOOGLE_CLIENT_SECRET",
  callbackURL: "/auth/google/callback",
  secret: "google_secret",
},
```

- **enabled**: Enables Google OAuth authentication.
- **clientID**: The Google OAuth Client ID.
- **clientSecret**: The Google OAuth Client Secret.
- **callbackURL**: The callback URL after Google authentication.
- **secret**: Secret key for verifying Google OAuth JWT tokens.

### **User Service Integration**

```javascript
user_service: {
  load_user: async (email) => userRepository.find(email),
},
```

- **load_user**: A function that fetches user details from a database based on the email provided.

### **Custom Password Checker**

```javascript
password_checker: async (inputPassword, storedPassword) => bcrypt.compare(inputPassword, storedPassword),
```

- **password_checker**: A function to verify if the provided password matches the stored password (used for login authentication).

### **Logging Configuration (logs)**

The logs option controls the level of logging displayed during authentication.

- **logs: true**: Enable detailed logging (info + warnings)
- **logs: false**: Only show warnings (errors and unauthorized attempts)

- **logs: true** → Displays info logs (successful authentication, token verification, etc.) along with warn logs.

- **logs: false** → Suppresses info logs and only shows warn logs (e.g., unauthorized access, expired tokens).

#### Example Logs When logs: true

```
[2025-02-05 10:30:15.234 AM] info: JWT Middleware Started...
[2025-02-05 10:30:16.456 AM] info: Authorization Header Found!
[2025-02-05 10:30:17.789 AM] info: JWT Verified Successfully!
```

- **Example Logs When logs**: false

```
[2025-02-05 10:30:18.234 AM] warn: Unauthorized access attempt (JWT missing)
```

## Authentication Flow

1. **JWT Authentication**

   - Users log in and receive a JWT token.
   - The token is sent in the `Authorization` header (`Bearer <token>`).
   - Middleware verifies the token and grants access.

2. **Session-Based Authentication**

   - User sessions are stored on the server.
   - Sessions persist across requests until they expire.
   - Middleware validates the session before granting access.

3. **Google OAuth Authentication**
   - Users log in via Google.
   - The system fetches the user’s profile information.
   - The user receives a JWT token for subsequent requests.

### `auth.config(config: Config): Router`

Initializes AuthCore with the provided configuration. Returns an Express router that should be mounted in your app.

### `auth.verify(): Middleware`

Middleware to verify user authentication based on the enabled strategy (JWT, session, or Google OAuth).

## API Endpoints

### **Login with JWT**

```http
POST /auth/jwt/login
```

### **Refresh JWT Token**

```http
POST /auth/jwt/refresh
```

### **Google OAuth Login**

```http
GET /auth/google/login
```

### **Google OAuth Callback**

```http
GET /auth/google/callback
```

### **Get User Details (Protected Route)**

```http
GET /me
Authorization: Bearer <token>
```

## Conclusion

Auth-Core provides a seamless way to integrate authentication into your Express.js applications with minimal configuration. It simplifies authentication logic and enhances security while maintaining flexibility.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your improvements.

## License

This project is licensed under the GPL-3.0 License.

---
