import "express-session";

declare module "express-session" {
  interface SessionData {
    user?: {
      type: string;
      [key: string]: any;
    };
  }
}
