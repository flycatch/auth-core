import { JwtPayload } from "jsonwebtoken";

/**
 * Represents the structure of a JWT payload containing user identification and token type.
 */
export interface JWTPayload extends JwtPayload {
  id: string;
  username: string;
  type: "refresh" | "access";
}

/**
 * Represents the JWT tokens issued during authentication, including access and optional refresh tokens.
 */
export interface JwtTokens {
  accessToken: string;
  refreshToken?: string;
}
