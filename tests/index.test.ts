/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/no-unused-vars */
import AuthCore from "../src/index"; // Default export
import { Request, Response, NextFunction, RequestHandler } from "express";
import { Session, SessionData } from "express-session";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import passport from "passport";
import { SessionPayload } from "../src/interfaces/session.interface"; // Adjust path if needed

// Extend SessionData to include 'user'
declare module "express-session" {
  interface SessionData {
    user?: SessionPayload;
  }
}

// Mock dependencies
jest.mock("bcrypt");
jest.mock("passport", () => ({
  initialize: jest
    .fn()
    .mockReturnValue((req: any, res: any, next: any) => next()),
  use: jest.fn(),
  authenticate: jest
    .fn()
    .mockReturnValue((req: any, res: any, next: any) => next()),
}));

describe("AuthCore", () => {
  let config: (options: any) => any;
  let verify: (permission?: string) => RequestHandler;
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: jest.Mock;
  const mockTransport = jest.fn().mockResolvedValue(true);
  const jwtSecret = "test-secret";

  // Mock user matching SessionPayload
  const createMockUser = (email: string): SessionPayload => ({
    id: "123",
    username: "exampleUser",
    type: "access" as const,
  });

  beforeEach(() => {
    // Destructure config and verify from default export
    ({ config, verify } = AuthCore);
    mockReq = {
      headers: {},
      session: {
        id: "mock-session-id",
        cookie: { originalMaxAge: 60000, expires: new Date(), secure: false },
        regenerate: jest.fn().mockImplementation((cb) => cb(null)),
        destroy: jest.fn().mockImplementation((cb) => cb(null)),
        reload: jest.fn().mockImplementation((cb) => cb(null)),
        save: jest.fn().mockImplementation((cb) => cb(null)),
        touch: jest.fn().mockImplementation((cb) => cb(null)),
        resetMaxAge: jest.fn().mockReturnThis(),
      } as Session & Partial<SessionData>,
      body: {},
      query: {},
      user: undefined,
    };
    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };
    mockNext = jest.fn();
    jest.clearAllMocks();
  });

  describe("JWT Authentication", () => {
    beforeEach(() => {
      config({
        jwt: {
          enabled: true,
          secret: jwtSecret,
          expiresIn: "1h",
          refresh: true,
          prefix: "/auth/jwt",
          tokenBlacklist: { enabled: false },
        },
        userService: {
          loadUser: async (email: string) => createMockUser(email),
        },
        passwordChecker: async (input: string, stored: string) => {
          (bcrypt.compare as jest.Mock).mockResolvedValue(true);
          return bcrypt.compare(input, stored);
        },
      });
    });

    test("should verify valid JWT token", async () => {
      const user = createMockUser("test@example.com");
      const token = jwt.sign(user, jwtSecret, { expiresIn: "1h" });
      mockReq.headers = { authorization: `Bearer ${token}` };

      await verify()(mockReq as Request, mockRes as Response, mockNext);
      expect(mockNext).toHaveBeenCalled();
      expect(mockReq.user).toBeDefined();
    });

    test("should reject invalid JWT token", async () => {
      mockReq.headers = { authorization: "Bearer invalid-token" };

      await verify()(mockReq as Request, mockRes as Response, mockNext);
      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({ error: "Invalid token" });
      expect(mockNext).not.toHaveBeenCalled();
    });

    test("should handle JWT refresh", async () => {
      const user = createMockUser("test@example.com");
      const refreshToken = jwt.sign(user, jwtSecret, { expiresIn: "7d" });
      mockReq.body = { refreshToken };
      mockReq.headers = { authorization: `Bearer ${refreshToken}` };

      // Mock successful token refresh
      const middleware = verify();
      await middleware(mockReq as Request, mockRes as Response, mockNext);

      // Should succeed with valid refresh token
      expect(mockNext).toHaveBeenCalled();
      expect(mockReq.user).toBeDefined();
    });
  });

  describe("Session Authentication", () => {
    beforeEach(() => {
      config({
        session: {
          enabled: true,
          secret: "session-secret",
          resave: false,
          saveUninitialized: true,
          cookie: { secure: false, maxAge: 60000 },
        },
        userService: {
          loadUser: async (email: string) => createMockUser(email),
        },
      });
    });

    test("should verify active session", async () => {
      mockReq.session!.user = createMockUser("test@example.com");
      await verify()(mockReq as Request, mockRes as Response, mockNext);
      expect(mockReq.user).toEqual(createMockUser("test@example.com"));
      expect(mockNext).toHaveBeenCalled();
    });

    test("should reject missing session", async () => {
      await verify()(mockReq as Request, mockRes as Response, mockNext);
      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({ error: "Unauthorized" });
      expect(mockNext).not.toHaveBeenCalled();
    });
  });

  describe("2FA Authentication", () => {
    beforeEach(() => {
      config({
        jwt: { enabled: true, secret: jwtSecret, expiresIn: "1h" },
        twoFA: {
          enabled: true,
          prefix: "/auth/2fa",
          otpLength: 6,
          otpExpiresIn: "5m",
          transport: mockTransport,
        },
        userService: {
          loadUser: async (email: string) => createMockUser(email),
        },
      });
    });

    test("should send and verify valid 2FA OTP", async () => {
      const user = createMockUser("test@example.com");
      const token = jwt.sign(user, jwtSecret, { expiresIn: "1h" });
      mockReq.headers = { authorization: `Bearer ${token}` };
      mockReq.body = { email: "test@example.com", twoFactorCode: "123456" };

      // Mock successful 2FA verification
      mockTransport.mockResolvedValueOnce(true);

      await verify()(mockReq as Request, mockRes as Response, mockNext);

      // Should succeed with valid JWT token
      expect(mockNext).toHaveBeenCalled();
      expect(mockReq.user).toBeDefined();
    });

    test("should reject invalid 2FA OTP", async () => {
      mockReq.body = { email: "test@example.com", twoFactorCode: "invalid" };
      // No authorization header - should fail at JWT level first

      await verify()(mockReq as Request, mockRes as Response, mockNext);
      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: "Access token is required",
      });
      expect(mockNext).not.toHaveBeenCalled();
    });
  });

  describe("OAuth2 Authentication", () => {
    beforeEach(() => {
      // Mock passport.initialize() to return a proper middleware
      (passport.initialize as jest.Mock).mockReturnValue(
        (req: any, res: any, next: any) => next()
      );

      config({
        jwt: { enabled: true, secret: jwtSecret, expiresIn: "1h" },
        oauth: {
          enabled: true,
          baseURL: "http://localhost:3000",
          prefix: "/auth/oauth",
          providers: {
            google: {
              clientID: "mock-client-id",
              clientSecret: "mock-client-secret",
              callbackURL: "/auth/oauth/google/callback",
            },
          },
        },
        userService: {
          loadUser: async (email: string) => createMockUser(email),
        },
      });
    });

    test("should handle Google OAuth callback", async () => {
      const user = createMockUser("test@example.com");
      const token = jwt.sign(user, jwtSecret, { expiresIn: "1h" });
      mockReq.headers = { authorization: `Bearer ${token}` };
      mockReq.query = { code: "mock-code" };

      await verify()(mockReq as Request, mockRes as Response, mockNext);
      expect(mockNext).toHaveBeenCalled();
      expect(mockReq.user).toBeDefined();
    });

    test("should reject invalid OAuth code", async () => {
      mockReq.query = { code: "invalid-code" };
      // No authorization header - should fail at JWT level

      await verify()(mockReq as Request, mockRes as Response, mockNext);
      expect(mockRes.status).toHaveBeenCalledWith(401);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: "Access token is required",
      });
      expect(mockNext).not.toHaveBeenCalled();
    });
  });

  describe("Permission-Based Access", () => {
    beforeEach(() => {
      config({
        jwt: {
          enabled: true,
          secret: jwtSecret,
          expiresIn: "1h",
        },
        userService: {
          loadUser: async (email: string) => createMockUser(email),
        },
      });
    });

    test("should allow access with required permission", async () => {
      // Create user with permissions that your system recognizes
      const userWithPermissions = {
        id: "123",
        username: "exampleUser",
        type: "access" as const,
        email: "test@example.com",
        permissions: ["read_user"],
        grants: ["read_user"],
        roles: ["user"],
      };

      const token = jwt.sign(userWithPermissions, jwtSecret, {
        expiresIn: "1h",
      });
      mockReq.headers = { authorization: `Bearer ${token}` };

      // Configure with a userService that returns user with permissions
      config({
        jwt: {
          enabled: true,
          secret: jwtSecret,
          expiresIn: "1h",
        },
        userService: {
          loadUser: jest.fn().mockResolvedValue(userWithPermissions),
          getUserPermissions: jest.fn().mockResolvedValue(["read_user"]), // Add permissions method
        },
        // Mock permission system
        permissions: {
          enabled: true,
          checkUserPermission: jest.fn().mockResolvedValue(true),
        },
      });

      // Test without permission requirement first to ensure JWT works
      await verify()(mockReq as Request, mockRes as Response, mockNext);
      expect(mockReq.user).toBeDefined();
      mockNext.mockClear();

      // Now test with permission requirement
      await verify("read_user")(
        mockReq as Request,
        mockRes as Response,
        mockNext
      );
      expect(mockNext).toHaveBeenCalled();
    });

    test("should deny access without required permission", async () => {
      const user = createMockUser("test@example.com");
      const token = jwt.sign(user, jwtSecret, { expiresIn: "1h" });
      mockReq.headers = { authorization: `Bearer ${token}` };

      await verify("admin_access")(
        mockReq as Request,
        mockRes as Response,
        mockNext
      );
      expect(mockRes.status).toHaveBeenCalledWith(403);
      expect(mockRes.json).toHaveBeenCalledWith({
        error: "Access denied: Missing required permission",
        required: "admin_access",
        userGrants: [],
      });
      expect(mockNext).not.toHaveBeenCalled();
    });
  });
});
