# NestJS Usage with Auth-Core

Auth-Core provides seamless authentication integration for **NestJS** applications, supporting **JWT**, **Session-based**, and **OAuth 2.0** authentication — all configurable through a unified API.

---

## Features

- ✅ **JWT Authentication** with Access and Refresh Tokens
- ✅ **Session-based Authentication** for persistent user sessions
- ✅ **OAuth 2.0 Login** (Google, GitHub, and custom providers)
- ✅ **Two-Factor Authentication (2FA)** support
- ✅ **Role and Permission-Based Access Control**
- ✅ Plug-and-play integration with NestJS Guards

---

## Installation

Install Auth-Core via npm:

```bash
npm install @flycatch/auth-core
```

---

## Configuration in NestJS

### 1. Configure Auth-Core in `main.ts`

Initialize Auth-Core just like in Express, but within your NestJS bootstrap function.

```typescript
import { NestFactory } from "@nestjs/core";
import { AppModule } from "./app.module";
import { config } from "@flycatch/auth-core";
import bcrypt from "bcrypt";

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  const userRepository = {
    async find(email: string) {
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
      },
      session: {
        enabled: true,
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
        providers: {
          google: {
            clientID: "GOOGLE_CLIENT_ID",
            clientSecret: "GOOGLE_CLIENT_SECRET",
            callbackURL: "/auth/google/callback",
            scope: ["profile", "email"],
          },
        },
      },
      userService: {
        loadUser: async (email) => userRepository.find(email),
        createUser: async (profile) => ({
          id: "new-user-id",
          email: profile.email,
          username: profile.username,
          grants: ["ROLE_USER"],
        }),
      },
      passwordChecker: async (inputPassword, storedPassword) =>
        bcrypt.compare(inputPassword, storedPassword),
      logs: true,
    })
  );

  await app.listen(3000);
  console.log(`🚀 Server running at http://localhost:3000`);
}

bootstrap();
```

---

### 2. Create a Custom `AuthGuard`

Use Auth-Core’s `verify()` middleware inside a NestJS Guard for route protection.

```typescript
import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from "@nestjs/common";
import { verify } from "@flycatch/auth-core";

@Injectable()
export class AuthGuard implements CanActivate {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest();
    const res = context.switchToHttp().getResponse();

    return new Promise((resolve, reject) => {
      const next = (err?: any) => {
        if (err) {
          return reject(
            new UnauthorizedException(err.message || "Unauthorized")
          );
        }
        resolve(true);
      };

      try {
        const verifyMiddleware = verify();
        verifyMiddleware(req, res, next);
      } catch (error: any) {
        reject(new UnauthorizedException("Authentication error"));
      }
    });
  }
}
```

> ✅ You can also pass permissions to `verify()` — e.g. `verify("admin_access")` — for role-based control.

---

### 3. Protect Routes in Your Controller

Use the custom guard to protect any route.

```typescript
import { Controller, Get, UseGuards, Req } from "@nestjs/common";
import { AuthGuard } from "./authguard.guard";

@Controller("user")
export class UserController {
  @Get("/")
  @UseGuards(AuthGuard)
  getUser(@Req() req) {
    return { message: "Access granted", user: req.user };
  }
}
```

---

### 4. Example with Role-Based Access

If your app uses permissions or roles (e.g., `"admin"`), extend your guard:

```typescript
@Injectable()
export class RoleGuard implements CanActivate {
  constructor(private requiredRole: string) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest();
    const res = context.switchToHttp().getResponse();

    return new Promise((resolve, reject) => {
      const next = (err?: any) => {
        if (err) return reject(new UnauthorizedException(err.message));
        if (!req.user?.grants?.includes(this.requiredRole)) {
          return reject(new UnauthorizedException("Access denied"));
        }
        resolve(true);
      };

      verify()(req, res, next);
    });
  }
}
```

Usage:

```typescript
@Controller("admin")
export class AdminController {
  @Get("/")
  @UseGuards(new RoleGuard("admin"))
  getAdminDashboard(@Req() req) {
    return { message: "Admin Access", user: req.user };
  }
}
```

---

## Supported Authentication Methods

| Method        | Description                                                     |
| ------------- | --------------------------------------------------------------- |
| **JWT**       | Token-based authentication with access & refresh tokens         |
| **Session**   | Persistent user sessions stored securely                        |
| **OAuth 2.0** | Social login via Google, GitHub, or custom providers            |
| **2FA**       | Optional OTP-based two-factor verification for sensitive logins |

---

## Testing Authentication

### JWT-Protected Route

```bash
curl -X GET http://localhost:3000/user \
  -H "Authorization: Bearer <your_jwt_token>"
```

### OAuth 2.0 Login

```bash
http://localhost:3000/auth/google
```

After successful login, user data is returned from `/user`.

---

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request.

---

## License

This project is licensed under the **GPL-3.0 License**.

---

## [⬅ Back to Main README](../README.md)
