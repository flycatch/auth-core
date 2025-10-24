import "express-session";
import { SessionPayload } from "../interfaces/session.interface";

declare module "express-session" {
  interface SessionData {
    oauthRedirectUri?: string;
    oauthProvider?: string;
    user?: SessionPayload;
  }
}
