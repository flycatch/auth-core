<!-- Here’s a quick example of how to use AuthCore in an Nest.js application.

## Import the Library

Install the required dependencies if not already installed:

### npm install @nestjs/passport passportjs

## Authentication Guard

Create a custom guard to use auth.verify() in your NestJS application:

#### authguard.ts file

```javascript
import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import authCore from 'passportjs'; // Import your auth library

@Injectable()
export class AuthGuard implements CanActivate {
  canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest();
    const res = context.switchToHttp().getResponse();

    return new Promise((resolve, reject) => {
      const next = (err?: any) => {
        if (err) {
          return reject(
            new UnauthorizedException(err.message || 'Unauthorized'),
          );
        }
        resolve(true); // Authentication passed
      };

      try {
        const verifyMiddleware = authCore.verify(); // Use the verify middleware
        verifyMiddleware(req, res, next);
      } catch (error: any) {
        reject(new UnauthorizedException('Authentication error'));
      }
    });
  }
}
```

### Controller Configuration

Use the custom guard to protect your routes:

### app.controller.ts

```javascript
import { Controller, Get, Request, UseGuards } from "@nestjs/common";
import { AuthGuard } from "./authguard/authguard.guard";

@Controller("user")
export class AppController {
  @Get("/")
  @UseGuards(AuthGuard)
  async getUser(@Request() req: any) {
    return { message: "Verification successful", user: req.user };
  }
}
```

### Initialize Authentication in main.ts

### main.ts

```javascript
import { NestFactory } from "@nestjs/core";
import { AppModule } from "./app.module";
import auth from "passportjs"; // Import the library

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Configure the authentication
  auth.config({
    jwt: {
      enabled: true,
      refresh: true,
      config: { secret: "your_jwt_secret" },
    },
    session: { enabled: true },
    google: {
      enabled: true,
      clientID: "your_client_id",
      clientSecret: "your_client_secret",
      callbackURL: "http://localhost:3000/auth/google/callback",
    },
  });

  await app.listen(3000);
}
bootstrap();
``` -->

# PassportJS Authentication Library

A unified authentication solution for **Express.js** and **NestJS** applications. This library supports **JWT**, **Session-based Authentication**, and **Google OAuth**, providing a seamless integration for both frameworks.

---

## Features

- **JWT Authentication** with Access and Refresh Tokens.
- **Session-based Authentication** for persistent user sessions.
- **Google OAuth2 Login** for social authentication.
- Middleware-based verification for secure routes.
- Easy-to-configure for both **Express.js** and **NestJS**.

---

## Installation

Install the library via npm:

```bash
npm install auth-core
```

---

## Usage

### Configuration for NestJS

#### Install Dependencies

```bash
npm install auth-core @nestjs/auth-core
```

#### Create an `AuthGuard`

Create a custom guard in `authguard.guard.ts`:

```typescript
import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from "@nestjs/common";
import authCore from "auth-core"; // Import the library

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
        resolve(true); // Authentication passed
      };

      try {
        const verifyMiddleware = authCore.verify();
        verifyMiddleware(req, res, next);
      } catch (error: any) {
        reject(new UnauthorizedException("Authentication error"));
      }
    });
  }
}
```

#### Controller Example

Define a controller to protect routes in `app.controller.ts`:

```typescript
import { Controller, Get, UseGuards, Req } from "@nestjs/common";
import { AuthGuard } from "./authguard.guard";

@Controller("user")
export class UserController {
  @Get("/")
  @UseGuards(AuthGuard)
  getUser(@Req() req) {
    return { user: req.user };
  }
}
```

#### Integrating Authentication Configuration in `main.ts`

### Set up authentication in your NestJS entry point:

```typescript
import { NestFactory } from "@nestjs/core";
import { AppModule } from "./app.module";
import auth from "auth-core"; // Import the library

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  auth.config({
    jwt: {
      enabled: true,
      refresh: true,
      config: { secret: "your_jwt_secret" },
    },
    session: {
      enabled: true,
      secret: "your_session_secret",
    },
    google: {
      enabled: true,
      clientID: "your_google_client_id",
      clientSecret: "your_google_client_secret",
      callbackURL: "http://localhost:3000/auth/google/callback",
    },
  });

  app.use(auth.initialize()); // Initialize authentication middleware
  await app.listen(3000);
}

bootstrap();
```

---

## Authentication Methods Supported

1. **JWT Authentication**

   - Provides token-based authentication with access and refresh tokens.
   - Tokens are validated using the `auth.verify()` middleware.

2. **Session-based Authentication**

   - Securely stores user data in the session.
   - Sessions are validated using the `auth.verify()` middleware.

3. **Google OAuth**
   - Enables login via Google.
   - The library handles redirection, callback, and verification seamlessly.

---

## Testing Authentication

### Protected Route

Once configured, access a protected route:

#### NestJS:

```bash
curl -X GET http://localhost:3000/user -H "Authorization: Bearer <your_jwt_token>"
```

### Google OAuth Login

1. Navigate to: `http://localhost:3000/auth/google`
2. Authenticate via Google.
3. Access your user details from `/user`.

---

## Contributing

Contributions are welcome! Fork the repository and create a PR with your changes.

---

## License

MIT License. See the `LICENSE` file for details.
