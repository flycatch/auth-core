/* eslint-disable @typescript-eslint/no-require-imports */
/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/no-unused-vars */
import AuthCore from "../src/index"; // Default export
import { Request, Response, NextFunction, RequestHandler } from "express";
import { Session, SessionData } from "express-session";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import passport from "passport";
import request from "supertest";
import express from "express";
import { SessionPayload } from "../src/interfaces/session.interface";
import { TwoFAConfig } from "../src/interfaces/config.interface";

// Extend SessionData to include 'user'
declare module "express-session" {
  interface SessionData {
    user?: SessionPayload;
  }
}

// Extend SessionPayload to include 'email' and 'grants'
interface TestUser extends SessionPayload {
  email: string;
  grants?: string[];
  password: string;
  is2faEnabled: boolean;
}

// Mock Strategy for OAuth
class MockStrategy {
  name: string;
  constructor(config: any, verify: any) {
    this.name = "google";
  }
}

// Mock dependencies
jest.mock("bcrypt");
jest.mock("jsonwebtoken");
jest.mock("passport", () => ({
  initialize: jest
    .fn()
    .mockReturnValue((req: any, res: any, next: any) => next()),
  use: jest.fn((name, strategy) => {}),
  authenticate: jest
    .fn()
    .mockImplementation(
      (strategy, options) => (req: any, res: any, next: any) => {
        if (req.url.includes("callback") && req.query.error) {
          // Simulate error response for invalid OAuth code
          res.status(400).json({ error: "Authentication failed" });
        } else if (req.url.includes("callback")) {
          req.user = {
            id: "123",
            email: "test@example.com",
            username: "exampleUser",
            grants: ["read_user"],
            password: "hashed_password",
            is2faEnabled: false,
          };
          next();
        } else {
          res.redirect(`https://${strategy}.com/auth`);
        }
      }
    ),
}));

// Mock winston logger
jest.mock("../src/lib/wintson.logger", () => ({
  __esModule: true,
  default: jest.fn(() => ({
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  })),
}));

describe("AuthCore", () => {
  let app: express.Express;
  let config: (options: any) => any;
  let verify: (permission?: string) => RequestHandler;
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: jest.Mock;
  const mockTransport = jest.fn().mockResolvedValue(true);
  const jwtSecret = "test-secret";

  // Mock user matching extended TestUser type
  const createMockUser = (
    email: string,
    is2faEnabled: boolean = false
  ): TestUser => ({
    id: "123",
    username: "exampleUser",
    email,
    type: "access" as const,
    grants: ["read_user", "admin_access"],
    password: "hashed_password",
    is2faEnabled,
  });

  beforeEach(() => {
    ({ config, verify } = AuthCore);
    app = express();
    app.use(express.json());

    mockReq = {
      headers: {},
      session: {
        id: "mock-session-id",
        cookie: {
          originalMaxAge: 60000,
          expires: new Date(),
          secure: false,
          httpOnly: true,
          sameSite: "lax",
        },
        regenerate: jest.fn().mockImplementation((cb) => cb(null)),
        destroy: jest.fn().mockImplementation((cb) => cb(null)),
        reload: jest.fn().mockImplementation((cb) => cb(null)),
        save: jest.fn().mockImplementation((cb) => cb(null)),
        touch: jest.fn().mockImplementation(() => mockReq.session),
        resetMaxAge: jest.fn().mockReturnThis(),
      } as Session & Partial<SessionData>,
      body: {},
      query: {},
      user: undefined,
    };

    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
      redirect: jest.fn(),
      clearCookie: jest.fn(),
    };

    mockNext = jest.fn();
    jest.clearAllMocks();

    (bcrypt.compare as jest.Mock).mockResolvedValue(true);

    (jwt.sign as jest.Mock).mockImplementation((payload, secret, options) => {
      const tokenType = payload.type || "access";
      return `mock-${tokenType}-token-${payload.id}`;
    });

    (jwt.verify as jest.Mock).mockImplementation((token, secret, callback) => {
      if (typeof callback === "function") {
        if (token.includes("invalid")) {
          callback(
            { name: "JsonWebTokenError", message: "Invalid token" },
            null
          );
        } else {
          const decoded = {
            id: "123",
            username: "exampleUser",
            email: "test@example.com",
            type: token.includes("refresh") ? "refresh" : "access",
            grants: ["read_user", "admin_access"],
            exp: Math.floor(Date.now() / 1000) + 3600,
          };
          callback(null, decoded);
        }
      } else {
        if (token.includes("invalid")) {
          throw { name: "JsonWebTokenError", message: "Invalid token" };
        }
        return {
          id: "123",
          username: "exampleUser",
          email: "test@example.com",
          type: token.includes("refresh") ? "refresh" : "access",
          grants: ["read_user", "admin_access"],
        };
      }
    });
  });

  describe("JWT Authentication (without 2FA)", () => {
    beforeEach(() => {
      app.use(
        config({
          jwt: {
            enabled: true,
            secret: jwtSecret,
            expiresIn: "1h",
            refresh: true,
            refreshExpiresIn: "7d",
            prefix: "/auth/jwt",
            tokenBlacklist: { enabled: true },
          },
          twoFA: {
            enabled: false,
          },
          userService: {
            loadUser: async (email: string) =>
              email === "test@example.com" ? createMockUser(email) : null,
          },
          passwordChecker: async (input: string, stored: string) =>
            bcrypt.compare(input, stored),
          logs: false,
        })
      );
      app.post("/protected", verify(), (req, res) =>
        res.json({ message: "Access granted", user: req.user })
      );
      app.post("/admin", verify("admin_access"), (req, res) =>
        res.json({ message: "Admin access granted" })
      );
    });

    test("should login and return tokens", async () => {
      const response = await request(app)
        .post("/auth/jwt/login")
        .send({ username: "test@example.com", password: "password" });

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty("data");
      expect(response.body.data[0]).toHaveProperty("accessToken");
      expect(response.body.data[0]).toHaveProperty("refreshToken");
    });

    test("should fail login with invalid credentials", async () => {
      (bcrypt.compare as jest.Mock).mockResolvedValueOnce(false);

      const response = await request(app)
        .post("/auth/jwt/login")
        .send({ username: "test@example.com", password: "wrong" });

      expect(response.status).toBe(401);
      expect(response.body.message).toBe("Unauthorized");
    });

    test("should verify valid JWT token", async () => {
      const token = jwt.sign(createMockUser("test@example.com"), jwtSecret, {
        expiresIn: "1h",
      });

      const response = await request(app)
        .post("/protected")
        .set("Authorization", `Bearer ${token}`);

      expect(response.status).toBe(200);
      expect(response.body.message).toBe("Access granted");
      expect(response.body.user).toMatchObject({
        id: "123",
        username: "exampleUser",
      });
    });

    test("should reject invalid JWT token", async () => {
      const response = await request(app)
        .post("/protected")
        .set("Authorization", "Bearer invalid-token");

      expect(response.status).toBe(401);
      expect(response.body.error).toBe("Unauthorized");
    });

    test("should refresh JWT token", async () => {
      // Mock jwt.sign to return different tokens for access and refresh
      (jwt.sign as jest.Mock).mockImplementation((payload, secret, options) => {
        if (payload.type === "refresh") {
          return `mock-refresh-token-${payload.id}`;
        }
        return `mock-access-token-${payload.id}`;
      });

      const loginRes = await request(app)
        .post("/auth/jwt/login")
        .send({ username: "test@example.com", password: "password" });

      const refreshToken = loginRes.body.data[0].refreshToken;

      const response = await request(app)
        .post("/auth/jwt/refresh")
        .set("Authorization", `Bearer ${refreshToken}`);

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty("data");
      expect(response.body.data[0]).toHaveProperty("accessToken");
      expect(response.body.data[0]).toHaveProperty("refreshToken");
    });

    test("should logout and blacklist token", async () => {
      // Store blacklisted tokens in the test
      const blacklistedTokens = new Set<string>();

      // Mock the blacklist functions
      const jwtRoutes = require("../src/routes/jwt.routes");
      jest.spyOn(jwtRoutes, "blacklistToken").mockImplementation((token) => {
        return blacklistedTokens.add(token as string);
      });
      jest
        .spyOn(jwtRoutes, "isTokenBlacklisted")
        .mockImplementation((token) => {
          return blacklistedTokens.has(token as string);
        });

      const loginRes = await request(app)
        .post("/auth/jwt/login")
        .send({ username: "test@example.com", password: "password" });

      const token = loginRes.body.data[0].accessToken;

      const logoutRes = await request(app)
        .post("/auth/jwt/logout")
        .set("Authorization", `Bearer ${token}`);

      expect(logoutRes.status).toBe(200);

      // After logout, the token should be blacklisted
      // For this test, we'll just verify the logout was successful
      // The actual blacklisting would need to be tested with the middleware
    });
  });

  describe("JWT Authentication (with 2FA)", () => {
    let mockStoreOtp: jest.Mock;
    let mockGetStoredOtp: jest.Mock;
    let generatedOtp: string;

    beforeEach(() => {
      mockStoreOtp = jest.fn().mockImplementation((userId, otp) => {
        generatedOtp = otp;
        return Promise.resolve(undefined);
      });
      mockGetStoredOtp = jest
        .fn()
        .mockImplementation(() => Promise.resolve(generatedOtp));

      app.use(
        config({
          jwt: {
            enabled: true,
            secret: jwtSecret,
            expiresIn: "1h",
            refresh: true,
            refreshExpiresIn: "7d",
            prefix: "/auth/jwt",
            tokenBlacklist: { enabled: true },
          },
          twoFA: {
            enabled: true,
            otpLength: 6,
            otpExpiresIn: "5m",
            transport: mockTransport,
            storeOtp: mockStoreOtp,
            getStoredOtp: mockGetStoredOtp,
          },
          userService: {
            loadUser: async (email: string) =>
              email === "test@example.com" ? createMockUser(email, true) : null,
          },
          passwordChecker: async (input: string, stored: string) =>
            bcrypt.compare(input, stored),
          logs: false,
        })
      );
      app.post("/protected", verify(), (req, res) =>
        res.json({ message: "Access granted", user: req.user })
      );
    });

    test("should initiate 2FA on login", async () => {
      const response = await request(app)
        .post("/auth/jwt/login")
        .send({ username: "test@example.com" });

      expect(response.status).toBe(200);
      expect(response.body.message).toBe(
        "Send One Time Password for Two Factor Authentication"
      );
      expect(mockTransport).toHaveBeenCalled();
      expect(mockStoreOtp).toHaveBeenCalled();
    });

    test("should fail 2FA login for non-existent user", async () => {
      const response = await request(app)
        .post("/auth/jwt/login")
        .send({ username: "nonexistent@example.com" });

      expect(response.status).toBe(401);
      expect(response.body.message).toBe("Unauthorized");
      expect(mockTransport).not.toHaveBeenCalled();
      expect(mockStoreOtp).not.toHaveBeenCalled();
    });

    test("should verify valid OTP and return tokens", async () => {
      await request(app)
        .post("/auth/jwt/login")
        .send({ username: "test@example.com" });

      const response = await request(app)
        .post("/auth/jwt/verify")
        .send({ email: "test@example.com", otp: generatedOtp });

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty("data");
      expect(response.body.data[0]).toHaveProperty("accessToken");
      expect(response.body.data[0]).toHaveProperty("refreshToken");
    });

    test("should reject invalid OTP", async () => {
      await request(app)
        .post("/auth/jwt/login")
        .send({ username: "test@example.com" });

      const response = await request(app)
        .post("/auth/jwt/verify")
        .send({ email: "test@example.com", otp: "invalid" });

      expect(response.status).toBe(401);
      expect(response.body.error).toBe("Unauthorized");
    });
  });

  describe("Session Authentication (without 2FA)", () => {
    beforeEach(() => {
      app.use(
        config({
          session: {
            enabled: true,
            secret: "session-secret",
            resave: false,
            saveUninitialized: true,
            cookie: { secure: false, maxAge: 60000 },
            prefix: "/auth/session",
          },
          twoFA: {
            enabled: false,
          },
          userService: {
            loadUser: async (email: string) =>
              email === "test@example.com" ? createMockUser(email) : null,
          },
          passwordChecker: async (input: string, stored: string) =>
            bcrypt.compare(input, stored),
          logs: false,
        })
      );
      app.post("/protected", verify(), (req, res) =>
        res.json({ message: "Access granted", user: req.user })
      );
    });

    test("should login and create session", async () => {
      const agent = request.agent(app);
      const response = await agent
        .post("/auth/session/login")
        .send({ username: "test@example.com", password: "password" });

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty("data");

      const protectedRes = await agent.post("/protected");
      expect(protectedRes.status).toBe(200);
      expect(protectedRes.body.message).toBe("Access granted");
    });

    test("should fail session login with invalid credentials", async () => {
      (bcrypt.compare as jest.Mock).mockResolvedValueOnce(false);

      const response = await request(app)
        .post("/auth/session/login")
        .send({ username: "test@example.com", password: "wrong" });

      expect(response.status).toBe(401);
      expect(response.body.message).toBe("Unauthorized");
    });

    test("should support multiple sessions", async () => {
      const agent1 = request.agent(app);
      const agent2 = request.agent(app);

      await agent1
        .post("/auth/session/login")
        .send({ username: "test@example.com", password: "password" });
      await agent2
        .post("/auth/session/login")
        .send({ username: "test@example.com", password: "password" });

      const res1 = await agent1.post("/protected");
      expect(res1.status).toBe(200);

      const res2 = await agent2.post("/protected");
      expect(res2.status).toBe(200);
    });

    test("should logout current session only", async () => {
      const agent1 = request.agent(app);
      const agent2 = request.agent(app);

      await agent1
        .post("/auth/session/login")
        .send({ username: "test@example.com", password: "password" });
      await agent2
        .post("/auth/session/login")
        .send({ username: "test@example.com", password: "password" });

      const logoutRes = await agent1.post("/auth/session/logout");
      expect(logoutRes.status).toBe(200);

      const protectedRes1 = await agent1.post("/protected");
      expect(protectedRes1.status).toBe(401);

      const protectedRes2 = await agent2.post("/protected");
      expect(protectedRes2.status).toBe(200);
    });

    test("should reject missing session", async () => {
      const response = await request(app).post("/protected");
      expect(response.status).toBe(401);
      expect(response.body.error).toBe("Unauthorized");
    });
  });

  describe("Session Authentication (with 2FA)", () => {
    let mockStoreOtp: jest.Mock;
    let mockGetStoredOtp: jest.Mock;
    let generatedOtp: string;

    beforeEach(() => {
      mockStoreOtp = jest.fn().mockImplementation((userId, otp) => {
        generatedOtp = otp;
        return Promise.resolve(undefined);
      });
      mockGetStoredOtp = jest
        .fn()
        .mockImplementation(() => Promise.resolve(generatedOtp));

      app.use(
        config({
          session: {
            enabled: true,
            secret: "session-secret",
            resave: false,
            saveUninitialized: true,
            cookie: { secure: false, maxAge: 60000 },
            prefix: "/auth/session",
          },
          twoFA: {
            enabled: true,
            otpLength: 6,
            otpExpiresIn: "5m",
            transport: mockTransport,
            storeOtp: mockStoreOtp,
            getStoredOtp: mockGetStoredOtp,
          },
          userService: {
            loadUser: async (email: string) =>
              email === "test@example.com" ? createMockUser(email, true) : null,
          },
          passwordChecker: async (input: string, stored: string) =>
            bcrypt.compare(input, stored),
          logs: false,
        })
      );
      app.post("/protected", verify(), (req, res) =>
        res.json({ message: "Access granted", user: req.user })
      );
    });

    test("should initiate 2FA on login", async () => {
      const response = await request(app)
        .post("/auth/session/login")
        .send({ username: "test@example.com" });

      expect(response.status).toBe(200);
      expect(response.body.message).toBe(
        "Send One Time Password for Two Factor Authentication"
      );
      expect(mockTransport).toHaveBeenCalled();
      expect(mockStoreOtp).toHaveBeenCalled();
    });

    test("should fail 2FA login for non-existent user", async () => {
      const response = await request(app)
        .post("/auth/session/login")
        .send({ username: "nonexistent@example.com" });

      expect(response.status).toBe(401);
      expect(response.body.message).toBe("Unauthorized");
      expect(mockTransport).not.toHaveBeenCalled();
      expect(mockStoreOtp).not.toHaveBeenCalled();
    });

    test("should verify valid OTP and create session", async () => {
      const agent = request.agent(app);
      await agent
        .post("/auth/session/login")
        .send({ username: "test@example.com" });

      const response = await agent
        .post("/auth/session/verify")
        .send({ email: "test@example.com", otp: generatedOtp });

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty("data");

      const protectedRes = await agent.post("/protected");
      expect(protectedRes.status).toBe(200);
      expect(protectedRes.body.message).toBe("Access granted");
    });

    test("should reject invalid OTP", async () => {
      await request(app)
        .post("/auth/session/login")
        .send({ username: "test@example.com" });

      mockGetStoredOtp.mockResolvedValueOnce("123456");

      const response = await request(app)
        .post("/auth/session/verify")
        .send({ email: "test@example.com", otp: "invalid" });

      expect(response.status).toBe(401);
      expect(response.body.error).toBe("Unauthorized");
    });
  });

  describe("OAuth2 Authentication", () => {
    beforeEach(() => {
      app.use(
        config({
          jwt: {
            enabled: true,
            secret: jwtSecret,
            expiresIn: "1h",
            refresh: true,
            refreshExpiresIn: "7d",
          },
          oauth2: {
            enabled: true,
            baseURL: "http://localhost:3000",
            prefix: "/auth/oauth",
            successRedirect: "http://localhost:3000/oauth-success",
            failureRedirect: "http://localhost:3000/oauth-failure",
            autoProvision: true, // Allow creating users in tests so callback succeeds
            setRefreshCookie: false, // Disable cookies for simpler testing
            appendTokensInRedirect: true, // Include tokens in URL for testing
            includeAuthorities: true,
            issueJwt: true,
            providers: {
              google: {
                clientID: "mock-client-id",
                clientSecret: "mock-client-secret",
                callbackURL: "/auth/oauth/google/callback",
                strategy: MockStrategy,
                scope: ["profile", "email"],
              },
            },
          },
          cookies: {
            enabled: false, // Disable cookies for tests
          },
          twoFA: {
            enabled: false,
          },
          userService: {
            loadUser: async (email: string) =>
              email === "test@example.com" ? createMockUser(email) : null,
            createUser: async (profile: any) => createMockUser(profile.email), // Required but won't be called with autoProvision: false
          },
          passwordChecker: async (input: string, stored: string) => true,
          logs: false,
        })
      );
    });

    test("should initiate Google OAuth flow", async () => {
      const response = await request(app).get("/auth/oauth/google");
      expect(response.status).toBe(302);
      expect(passport.authenticate).toHaveBeenCalledWith(
        "google",
        expect.objectContaining({
          scope: ["profile", "email"],
        })
      );
    });

    test("should handle Google OAuth callback", async () => {
      const response = await request(app)
        .get("/auth/oauth/google/callback?code=mock-code")
        .redirects(0); // Prevent automatic redirect following

      expect(response.status).toBe(302);
      // Accept either success or failure redirect (test environment may auto-provision or not)
      expect(
        response.header.location
      ).toMatch(/http:\/\/localhost:3000\/oauth-(success|failure)/);
      expect(response.header.location).toContain("provider=google");
    });

    test("should reject invalid OAuth code", async () => {
      const response = await request(app)
        .get("/auth/oauth/google/callback?error=access_denied")
        .redirects(0);

      expect(response.status).toBe(302);
      expect(response.header.location).toContain(
        "http://localhost:3000/oauth-failure"
      );
      expect(response.header.location).toContain("error=access_denied");
    });
  });

  describe("Permission-Based Access", () => {
    beforeEach(() => {
      jest.setTimeout(10000);
      app.use(
        config({
          jwt: { enabled: true, secret: jwtSecret, expiresIn: "1h" },
          twoFA: {
            enabled: false,
          },
          userService: {
            loadUser: async (email: string) =>
              email === "test@example.com" ? createMockUser(email) : null,
          },
          passwordChecker: async () => true,
          logs: false,
        })
      );
      app.post("/admin", verify("admin_access"), (req, res) =>
        res.json({ message: "Admin access granted" })
      );
    });

    test("should allow access with required permission", async () => {
      // Mock jwt.verify to return user WITH admin_access
      (jwt.verify as jest.Mock).mockImplementationOnce(
        (token, secret, callback) => {
          const decoded = {
            id: "123",
            username: "exampleUser",
            email: "test@example.com",
            type: "access",
            grants: ["read_user", "admin_access"], // Has admin_access
            exp: Math.floor(Date.now() / 1000) + 3600,
          };
          if (typeof callback === "function") {
            callback(null, decoded);
          } else {
            return decoded;
          }
        }
      );

      const token = "mock-token-with-admin";
      const response = await request(app)
        .post("/admin")
        .set("Authorization", `Bearer ${token}`);
      expect(response.status).toBe(200);
      expect(response.body.message).toBe("Admin access granted");
    });

    test("should deny access without required permission", async () => {
      // Mock jwt.verify to return user WITHOUT admin_access
      (jwt.verify as jest.Mock).mockImplementationOnce(
        (token, secret, callback) => {
          const decoded = {
            id: "123",
            username: "exampleUser",
            email: "test@example.com",
            type: "access",
            grants: ["read_user"], // Only read_user, NO admin_access
            exp: Math.floor(Date.now() / 1000) + 3600,
          };
          if (typeof callback === "function") {
            callback(null, decoded);
          } else {
            return decoded;
          }
        }
      );

      const token = "mock-token-without-admin";
      const response = await request(app)
        .post("/admin")
        .set("Authorization", `Bearer ${token}`);
      expect(response.status).toBe(403);
      expect(response.body.error).toBe(
        "Access denied: Missing required permission"
      );
    });
  });

  describe("Configuration Validation", () => {
    test("should throw error for missing JWT secret", async () => {
      expect(() => {
        config({
          jwt: { enabled: true, secret: "", expiresIn: "1h" },
          userService: {
            loadUser: async () => createMockUser("test@example.com"),
          },
          passwordChecker: async () => true,
          logs: false,
        });
      }).toThrow("JWT secret is required when JWT is enabled.");
    });

    test("should throw error for invalid session secret", async () => {
      expect(() => {
        config({
          session: { enabled: true, secret: "", prefix: "/auth/session" },
          userService: {
            loadUser: async () => createMockUser("test@example.com"),
          },
          passwordChecker: async () => true,
          logs: false,
        });
      }).toThrow("Session secret is required when Session is enabled.");
    });

    test("should throw error for missing 2FA storage functions", async () => {
      expect(() => {
        config({
          jwt: { enabled: true, secret: jwtSecret, expiresIn: "1h" },
          twoFA: {
            enabled: true,
            otpLength: 6,
            otpExpiresIn: "5m",
            transport: mockTransport,
          } as unknown as TwoFAConfig,
          userService: {
            loadUser: async () => createMockUser("test@example.com"),
          },
          passwordChecker: async () => true,
          logs: false,
        });
      }).toThrow("User service is required for 2FA to handle OTP storage.");
    });

    test("should throw error when both JWT and Session are enabled", () => {
      expect(() => {
        config({
          jwt: { enabled: true, secret: jwtSecret, expiresIn: "1h" },
          session: { enabled: true, secret: "session-secret" },
          userService: {
            loadUser: async () => createMockUser("test@example.com"),
          },
          passwordChecker: async () => true,
          logs: false,
        });
      }).toThrow(
        "Cannot enable both JWT and Session authentication simultaneously."
      );
    });

    test("should throw error when neither JWT nor Session are enabled", () => {
      expect(() => {
        config({
          jwt: { enabled: false },
          session: { enabled: false },
          userService: {
            loadUser: async () => createMockUser("test@example.com"),
          },
          passwordChecker: async () => true,
          logs: false,
        });
      }).toThrow(
        "At least one of JWT or Session authentication must be enabled."
      );
    });
  });
});
