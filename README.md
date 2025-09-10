# Auth-Core

Auth-Core is a unified authentication middleware for Node.js applications, supporting JWT-based authentication, session-based authentication, and OAuth authentication. This package simplifies authentication management by providing middleware functions that handle authentication flows seamlessly.

## Features

- **JWT Authentication** with optional token blacklisting and logout
- **Session-based Authentication** with multiple sessions per user
- **OAuth Authentication** (Google, Facebook, GitHub, Twitter, and custom providers)
- **Two-Factor Authentication (2FA)**
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
    return { id: "123", email, username: "exampleUser", grants: ["read_user"] };
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
      // Optional: Enable token blacklisting for secure logout
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
    oauth: {
      enabled: false,
      baseURL: "http://localhost:3000",
      prefix: "/auth/oauth",
      providers: {
        google: {
          clientID: "GOOGLE_CLIENT_ID",
          clientSecret: "GOOGLE_CLIENT_SECRET",
          callbackURL: "/auth/oauth/google/callback",
        },
      },
    },
    twoFA: {
      enabled: false,
      prefix: "/auth/2fa",
      otpLength: 6,
      otpExpiresIn: "5m",
    },
    userService: {
      loadUser: async (email) => userRepository.find(email),
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
    enabled: false, // Set to true for server-side logout
    customStorage: { /* Custom storage implementation */ }
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

### **OAuth Authentication**

```javascript
oauth: {
  enabled: true,
  baseURL: "http://localhost:3000",
  prefix: "/auth/oauth",
  providers: {
    google: {
      clientID: "GOOGLE_CLIENT_ID",
      clientSecret: "GOOGLE_CLIENT_SECRET",
      callbackURL: "/auth/oauth/google/callback",
      scope: ["profile", "email"]
    },
    github: {
      clientID: "GITHUB_CLIENT_ID",
      clientSecret: "GITHUB_CLIENT_SECRET"
    }
  },
  customProviders: {
    myProvider: {
      strategy: MyCustomStrategy,
      clientID: "CLIENT_ID",
      clientSecret: "CLIENT_SECRET"
    }
  }
}
```

- **enabled**: Enables OAuth authentication.
- **providers**: Supported providers (google, facebook, github, twitter).
- **customProviders**: Add custom OAuth providers.

### **Two-Factor Authentication**

```javascript
twoFA: {
  enabled: true,
  prefix: "/auth/2fa",
  otpLength: 6,
  otpExpiresIn: "5m",
  transport: async (otp, user) => {
    // Send OTP via SMS/Email
    console.log(`Send OTP ${otp} to ${user.email}`);
  }
}
```

### **User Service Integration**

```javascript
userService: {
  loadUser: async (email) => userRepository.find(email),
}
```

### **Custom Password Checker**

```javascript
passwordChecker: async (inputPassword, storedPassword) =>
  bcrypt.compare(inputPassword, storedPassword);
```

## API Endpoints

All endpoints use the configured prefix. Default prefixes shown below:

### **JWT Authentication**

- **POST** `/auth/jwt/login` - User login
- **POST** `/auth/jwt/refresh` - Refresh access token
- **POST** `/auth/jwt/logout` - Logout (simple or with blacklisting)

### **Session Authentication**

- **POST** `/auth/session/login` - User login (creates new session)
- **POST** `/auth/session/logout` - Logout current session

### **OAuth Authentication**

- **GET** `/auth/{provider}` - Initiate OAuth login
- **GET** `/auth/{provider}/callback` - OAuth callback

### **Two-Factor Authentication**

- **POST** `/auth/2fa/send-otp` - Generate OTP
- **POST** `/auth/2fa/verify` - Verify OTP

## Authentication Flow

### **JWT Authentication**

1. User logs in and receives JWT tokens (access + refresh if enabled)
2. Client includes token in `Authorization: Bearer <token>` header
3. Middleware verifies token and grants access
4. Optional: Token blacklisting for secure server-side logout

### **Session Authentication**

1. User logs in and server creates session
2. Session cookie is automatically sent with requests
3. Middleware validates session and grants access
4. Supports multiple concurrent sessions per user

### **OAuth Authentication**

1. User initiates OAuth flow with provider
2. After successful authentication, returns JWT tokens or creates session
3. Subsequent requests use JWT or session authentication

## Logout Behavior

### **JWT Logout**

- **Simple Logout** (default): Client removes tokens, server logs event
- **Advanced Logout** (with blacklisting): Server immediately invalidates tokens

### **Session Logout**

- Destroys current session only
- Other sessions remain active (multi-session support)

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
