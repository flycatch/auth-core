# Auth-Core

Auth-Core is a unified authentication middleware for Node.js applications, supporting JWT-based authentication, session-based authentication, and OAuth 2.0 authentication. This package simplifies authentication management by providing middleware functions that handle authentication flows seamlessly.

## Features

- **JWT Authentication** with optional token blacklisting and logout
- **Session-based Authentication** with multiple sessions per user
- **OAuth 2.0 Authentication** (Google, GitHub, and custom providers)
- **Two-Factor Authentication (2FA)** integrated with JWT and session-based authentication
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
    return {
      id: "123",
      email,
      username: "exampleUser",
      grants: ["read_user"],
      is2faEnabled: false,
    };
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
      tokenBlacklist: {
        enabled: false, // Set to true for server-side logout
      },
    },
    session: {
      enabled: false,
      prefix: "/auth/session",
      secret: "my_session_secret",
      resave: false,
      saveUninitialized: true,
      cookie: { secure: false, maxAge: 60000 },
    },
    oauth2: {
      enabled: true,
      baseURL: "http://localhost:3000",
      prefix: "/auth",
      successRedirect: "http://localhost:3000/oauth-success",
      failureRedirect: "http://localhost:3000/oauth-failure",
      autoProvision: true,
      defaultRole: "ROLE_USER",
      setRefreshCookie: true,
      appendTokensInRedirect: false,
      includeAuthorities: true,
      issueJwt: true,
      providers: {
        google: {
          clientID: "GOOGLE_CLIENT_ID",
          clientSecret: "GOOGLE_CLIENT_SECRET",
          callbackURL: "/auth/google/callback",
          scope: ["profile", "email"],
        },
      },
    },
    cookies: {
      enabled: true,
      name: "AuthRefreshToken",
      httpOnly: true,
      secure: false,
      sameSite: "Strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: "/",
    },
    twoFA: {
      enabled: false,
      prefix: "/auth/2fa",
      otpLength: 6,
      otpExpiresIn: "5m",
      storeOtp: async (userId, otp, expiresInMs) => {
        // Implement OTP storage logic
        console.log(
          `Storing OTP ${otp} for user ${userId}, expires in ${expiresInMs}ms`
        );
      },
      getStoredOtp: async (userId) => {
        // Implement OTP retrieval logic
        return null;
      },
    },
    userService: {
      loadUser: async (email) => userRepository.find(email),
      createUser: async (profile) => {
        return {
          id: "new-user-id",
          email: profile.email,
          username: profile.username,
          grants: [profile.defaultRole || "ROLE_USER"],
        };
      },
    },
    passwordChecker: async (inputPassword, storedPassword) =>
      bcrypt.compare(inputPassword, storedPassword),
    logs: true,
  })
);

// Protected Route
app.get("/user", verify(), (req, res) => {
  res.json({ message: "Access granted", user: req.user });
});

// Protected Route with specific permission
app.get("/admin", verify("admin"), (req, res) => {
  res.json({ message: "Admin access granted", user: req.user });
});

app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});
```

## Configuration Options

### **JWT Authentication**

```javascript
jwt: {
  enabled: true,
  secret: "my_jwt_secret",
  expiresIn: "1h",
  refresh: true,
  refreshExpiresIn: "7d",
  prefix: "/auth/jwt",
  revokeOnRefresh: true,
  tokenBlacklist: {
    enabled: false,
    storageService: {
      add: async (token, expiresAt) => { /* Custom add logic */ },
      has: async (token) => { /* Custom check logic */ },
      remove: async (token) => { /* Custom remove logic */ },
      clear: async () => { /* Custom clear logic */ },
    },
    onLogoutAll: async (userId) => { /* Custom logout all logic */ },
  }
}
```

- **enabled**: Enables or disables JWT authentication.
- **secret**: The secret key used to sign JWT tokens.
- **expiresIn**: Access token expiration time.
- **refresh**: Enables refresh token support.
- **refreshExpiresIn**: Refresh token expiration time.
- **prefix**: The route prefix for JWT authentication endpoints.
- **tokenBlacklist**: Optional token blacklisting for secure logout.
  - **enabled**: Enables server-side token blacklisting.
  - **storageService**: Custom storage for blacklisted tokens.
  - **onLogoutAll**: Callback for custom cleanup on logout-all.

### **Session-Based Authentication**

```javascript
session: {
  enabled: true,
  prefix: "/auth/session",
  secret: "my_session_secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}
```

- **enabled**: Enables session-based authentication.
- **prefix**: Route prefix for session authentication endpoints.
- **secret**: Session secret key.
- **resave/saveUninitialized**: Express session options.
- **cookie**: Session cookie configuration.

**Note**: Session authentication supports multiple concurrent sessions per user. Each login creates a new independent session.

### **OAuth 2.0 Authentication**

```javascript
oauth2: {
  enabled: true,
  baseURL: "http://localhost:3000",
  prefix: "/auth",
  successRedirect: "http://localhost:3000/oauth-success",
  failureRedirect: "http://localhost:3000/oauth-failure",
  autoProvision: true,
  defaultRole: "ROLE_USER",
  setRefreshCookie: true,
  appendTokensInRedirect: false,
  includeAuthorities: true,
  issueJwt: true,
  providers: {
    google: {
      clientID: "GOOGLE_CLIENT_ID",
      clientSecret: "GOOGLE_CLIENT_SECRET",
      callbackURL: "/auth/google/callback",
      scope: ["profile", "email"],
    },
    github: {
      clientID: "GITHUB_CLIENT_ID",
      clientSecret: "GITHUB_CLIENT_SECRET",
      callbackURL: "/auth/github/callback",
    },
  },
}
```

- **enabled**: Enables OAuth 2.0 authentication.
- **baseURL**: Base URL for callback redirects.
- **prefix**: Route prefix for OAuth authentication endpoints.
- **successRedirect**: URL to redirect after successful OAuth authentication.
- **failureRedirect**: URL to redirect after failed OAuth authentication.
- **autoProvision**: Automatically create users if they don't exist.
- **defaultRole**: Default role assigned to new users.
- **setRefreshCookie**: Set refresh token as HTTP-only cookie.
- **appendTokensInRedirect**: Include tokens in redirect URL.
- **includeAuthorities**: Include user grants in JWT tokens.
- **issueJwt**: Issue JWT tokens for OAuth users.
- **providers**: Supported providers (e.g., Google, GitHub).

### **Cookie Configuration**

```javascript
cookies: {
  enabled: true,
  name: "AuthRefreshToken",
  httpOnly: true,
  secure: false,
  sameSite: "Strict",
  maxAge: 7 * 24 * 60 * 60 * 1000,
  path: "/",
}
```

- **enabled**: Enables cookie support.
- **name**: Cookie name for refresh token.
- **httpOnly**: Prevents client-side JavaScript access.
- **secure**: Only send over HTTPS.
- **sameSite**: CSRF protection setting.
- **maxAge**: Cookie expiration time.
- **path**: Cookie path.

### **Two-Factor Authentication**

```javascript
twoFA: {
  enabled: true,
  prefix: "/auth/2fa",
  otpLength: 6,
  otpType: "numeric",
  otpExpiresIn: "5m",
  transport: async (otp, user) => {
    console.log(`Send OTP ${otp} to ${user.email}`);
  },
  storeOtp: async (userId, otp, expiresInMs) => {
    // Implement OTP storage
  },
  getStoredOtp: async (userId) => {
    // Implement OTP retrieval
    return null;
  },
  clearOtp: async (userId) => {
    // Implement OTP cleanup
  },
}
```

- **enabled**: Enables 2FA for JWT or session-based authentication.
- **prefix**: Route prefix for 2FA endpoints.
- **otpLength**: Length of the OTP.
- **otpType**: Type of OTP (numeric or alphanumeric).
- **otpExpiresIn**: OTP expiration time.
- **transport**: Function to send OTP to the user.
- **storeOtp**: Function to store OTP securely.
- **getStoredOtp**: Function to retrieve stored OTP.
- **clearOtp**: Optional function to clear OTP after verification.

### **User Service Integration**

```javascript
userService: {
  loadUser: async (email) => userRepository.find(email),
  createUser: async (profile) => {
    // Create new user during OAuth flow
    return {
      id: "new-user-id",
      email: profile.email,
      username: profile.username,
      grants: [profile.defaultRole || "ROLE_USER"],
    };
  },
}
```

- **loadUser**: Load user by email (required).
- **createUser**: Create new user during OAuth auto-provisioning (required for OAuth).

### **Custom Password Checker**

```javascript
passwordChecker: async (inputPassword, storedPassword) =>
  bcrypt.compare(inputPassword, storedPassword);
```

## API Endpoints

All endpoints use the configured prefix. Default prefixes shown below:

### **JWT Authentication**

- **POST** `/auth/jwt/login` - Initiate user login (sends OTP if 2FA enabled, else returns tokens)
- **POST** `/auth/jwt/verify` - Verify OTP for 2FA and return tokens
- **POST** `/auth/jwt/refresh` - Refresh access token
- **POST** `/auth/jwt/logout` - Logout (simple or with blacklisting)
- **POST** `/auth/jwt/logout-all` - Logout all sessions (requires blacklisting enabled)

### **Session Authentication**

- **POST** `/auth/session/login` - Initiate user login (sends OTP if 2FA enabled, else creates session)
- **POST** `/auth/session/verify` - Verify OTP for 2FA and create session
- **POST** `/auth/session/logout` - Logout current session

### **OAuth 2.0 Authentication**

- **GET** `/auth/{provider}` - Initiate OAuth login
- **GET** `/auth/{provider}/callback` - OAuth callback
- **GET** `/auth/error` - OAuth error redirect

### **Two-Factor Authentication**

- Integrated with JWT and session authentication flows.
- If enabled, `/login` endpoints trigger OTP generation and transport.
- Use `/verify` endpoints to validate OTP and complete login.

## Authentication Flow

### **JWT Authentication**

1. User sends login request to `/auth/jwt/login`.
2. If 2FA is enabled, server sends OTP and user submits it to `/auth/jwt/verify`.
3. On successful verification (or directly if 2FA is disabled), server returns JWT tokens (access + refresh if enabled).
4. Client includes token in `Authorization: Bearer <token>` header.
5. Middleware verifies token and grants access.
6. Optional: Token blacklisting for secure server-side logout.

### **Session Authentication**

1. User sends login request to `/auth/session/login`.
2. If 2FA is enabled, server sends OTP and user submits it to `/auth/session/verify`.
3. On successful verification (or directly if 2FA is disabled), server creates a new session.
4. Session cookie is automatically sent with requests.
5. Middleware validates session and grants access.
6. Supports multiple concurrent sessions per user.

### **OAuth 2.0 Authentication**

1. User initiates OAuth flow with provider via `/auth/{provider}`.
2. After successful authentication, provider redirects to `/auth/{provider}/callback`.
3. Server processes authentication and auto-creates user if enabled.
4. Server redirects to success URL with tokens as cookies.
5. Subsequent requests use JWT or session authentication.

## Logout Behavior

### **JWT Logout**

- **Simple Logout** (default): Client removes tokens, server logs event.
- **Advanced Logout** (with blacklisting): Server invalidates tokens.
- **Logout All**: Invalidates all tokens for a user (requires blacklisting).

### **Session Logout**

- Destroys current session only.
- Other sessions remain active (multi-session support).

## Middleware Usage

```javascript
// Protect any route
app.get("/protected", verify(), (req, res) => {
  res.json({ user: req.user });
});

// Require specific permission
app.get("/admin", verify("admin_access"), (req, res) => {
  res.json({ message: "Admin only" });
});
```

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your improvements.

## License

This project is licensed under the GPL-3.0 License.

## More

- [How to use in Nest JS](./docs/nestjs_usage.md)
