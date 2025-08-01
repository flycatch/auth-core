/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/no-unused-vars */
import express, { Request, Response, NextFunction } from "express";
import { Config } from "../src/interfaces/config.interface";
import createLogger from "../src/lib/wintson.logger";
import jwtRoutes from "../src/routes/jwt.routes";
import sessionRoutes from "../src/routes/session.routes";
import setupGoogleRoutes from "../src/routes/setup-google-oath.routes";
import setupSession from "../src/config/Session.config";
import setupGoogleOath from "../src/config/GoogleOath.config";
import jwtMiddleware from "../src/middlewares/jwt.middleware";
import sessionMiddleware from "../src/middlewares/session.middleware";
import googleAuthMiddleware from "../src/middlewares/googleAuth.middleware";
import indexModule from "../src/index";

jest.mock("../src/lib/wintson.logger", () => () => ({
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
}));
jest.mock("../src/routes/jwt.routes");
jest.mock("../src/routes/session.routes");
jest.mock("../src/routes/setup-google-oath.routes");
jest.mock("../src/config/Session.config");
jest.mock("../src/config/GoogleOath.config");
jest.mock("../src/middlewares/jwt.middleware", () => jest.fn(() => (req: any, res: any, next: any) => next()));
jest.mock("../src/middlewares/session.middleware", () => jest.fn(() => (req: any, res: any, next: any) => next()));
jest.mock("../src/middlewares/googleAuth.middleware", () => jest.fn(() => (req: any, res: any, next: any) => next()));

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

  it("should set up Google OAuth routes if enabled", () => {
    const config: Config = { google: { enabled: true } } as any;
    const router = indexModule.config(config);
    expect(setupGoogleOath).toHaveBeenCalled();
    expect(setupGoogleRoutes).toHaveBeenCalled();
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

  it("should use googleAuthMiddleware if Google OAuth is enabled", () => {
    const config: Config = { google: { enabled: true } } as any;
    indexModule.config(config);
    const middleware = indexModule.verify();
    middleware(req as Request, res as Response, next);
    expect(googleAuthMiddleware).toHaveBeenCalled();
  });

  it("should return 500 if no authentication is configured", () => {
    const config: Config = {} as any;
    indexModule.config(config);
    const middleware = indexModule.verify();
    middleware(req as Request, res as Response, next);
    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.json).toHaveBeenCalledWith({ error: "Authentication not configured" });
  });

  it("should return 403 if permission is missing", () => {
    const config: Config = { jwt: { enabled: true } } as any;
    indexModule.config(config);
    const middleware = indexModule.verify("admin");
    req.user = { grands: ["user"] };
    middleware(req as Request, res as Response, next);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({ error: "Access denied: Missing required permission" });
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
