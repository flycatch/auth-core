/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/no-unused-vars */
import express, { Request, Response, NextFunction } from "express";
import { Config } from "../src/interfaces/config.interface";
import createLogger from "../src/lib/wintson.logger";
import jwtRoutes from "../src/routes/jwt.routes";
import sessionRoutes from "../src/routes/session.routes";
import setupSession from "../src/config/session.config";
import jwtMiddleware from "../src/middlewares/jwt.middleware";
import sessionMiddleware from "../src/middlewares/session.middleware";
import twoFactorAuthRoutes from "../src/routes/two-factor-auth.routes";
import setupOauth from "../src/config/oauth.config";
import oauthRoutes from "../src/routes/oauth.routes";
import indexModule from "../src/index";
import { User } from "../src/interfaces/user.interface";

jest.mock("../src/lib/wintson.logger", () => () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
}));
jest.mock("../src/routes/jwt.routes");
jest.mock("../src/routes/session.routes");
jest.mock("../src/routes/two-factor-auth.routes");
jest.mock("../src/config/session.config");
jest.mock("../src/config/oauth.config");
jest.mock("../src/routes/oauth.routes");
jest.mock("../src/middlewares/jwt.middleware", () =>
  jest.fn(() => (req: any, res: any, next: any) => next())
);
jest.mock("../src/middlewares/session.middleware", () =>
  jest.fn(() => (req: any, res: any, next: any) => next())
);

describe("index.ts config function", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  it("should set up JWT routes if enabled", () => {
    const config: Config = { jwt: { enabled: true } } as any;
    const router = indexModule.config(config);
    expect(jwtRoutes).toHaveBeenCalled();
  });

  it("should set up session routes if enabled", () => {
    const config: Config = { session: { enabled: true } } as any;
    const router = indexModule.config(config);
    expect(setupSession).toHaveBeenCalled();
    expect(sessionRoutes).toHaveBeenCalled();
  });

  it("should setup Twofactor Auth routes if enabled", () => {
    const config: Config = { twoFA: { enabled: true } } as any;
    const router = indexModule.config(config);
    expect(twoFactorAuthRoutes).toHaveBeenCalled();
  });

  it("should setup  OAuth routes if it's enabled", () => {
    const config: Config = {
      oauth: {
        enabled: true,
        providers: {},
      },
      userService: {
        loadUser: function (email: string): Promise<User | null | undefined> {
          throw new Error("Function not implemented.");
        },
      },
      passwordChecker: function (
        inputPassword: string,
        storedPassword: string
      ): Promise<boolean> {
        throw new Error("Function not implemented.");
      },
      logs: false,
    };
    const router = indexModule.config(config);
    expect(setupOauth).toHaveBeenCalled();
    expect(oauthRoutes).toHaveBeenCalled();
  });
});

describe("index.ts verify middleware", () => {
  let req: Partial<Request>;
  let res: Partial<Response>;
  let next: NextFunction;

  beforeEach(() => {
    req = {};
    res = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn(),
    };
    next = jest.fn();
    jest.clearAllMocks();
  });

  it("should use jwtMiddleware if JWT is enabled", () => {
    const config: Config = { jwt: { enabled: true } } as any;
    indexModule.config(config);
    const middleware = indexModule.verify();
    middleware(req as Request, res as Response, next);
    expect(jwtMiddleware).toHaveBeenCalled();
  });

  it("should use sessionMiddleware if session is enabled", () => {
    const config: Config = { session: { enabled: true } } as any;
    indexModule.config(config);
    const middleware = indexModule.verify();
    middleware(req as Request, res as Response, next);
    expect(sessionMiddleware).toHaveBeenCalled();
  });

  it("should return 500 if no authentication is configured", () => {
    const config: Config = {} as any;
    indexModule.config(config);
    const middleware = indexModule.verify();
    middleware(req as Request, res as Response, next);
    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.json).toHaveBeenCalledWith({
      error: "Authentication not configured",
    });
  });

  it("should return 403 if permission is missing", () => {
    const config: Config = { jwt: { enabled: true } } as any;
    indexModule.config(config);
    const middleware = indexModule.verify("admin");
    req.user = { grands: ["user"] };
    middleware(req as Request, res as Response, next);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({
      error: "Access denied: Missing required permission",
    });
  });

  it("should call next if permission is present", () => {
    const config: Config = { jwt: { enabled: true } } as any;
    indexModule.config(config);
    const middleware = indexModule.verify("admin");
    req.user = { grands: ["admin"] };
    middleware(req as Request, res as Response, next);
    expect(next).toHaveBeenCalled();
  });
});
