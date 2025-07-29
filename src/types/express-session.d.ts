import "express-session";

declare module "express-session" {
  interface SessionData {
    user?: {
      type: string;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      [key: string]: any;
    };
  }
}
