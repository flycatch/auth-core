import "express-session";
import { SessionPayload } from "../interfaces/session.interface";

declare module "express-session" {
  interface SessionData {
    oauthPopup?: boolean;
    oauthState?: string;
    oauthRedirectUrl?: string;
    oauthProvider?: string;
    user?: SessionPayload;
  }
}
