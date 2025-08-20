import { JwtConfig } from "../interfaces/config.interface";
import jwt from "jsonwebtoken";
import { User } from "../interfaces/user.interface";
import { JwtTokens } from "../interfaces/jwt.interface";

/**
 * Generates JWT access and refresh tokens for a user
 *
 * @param config - JWT configuration object containing secret, expiration times, and refresh settings
 * @param user - User object containing id, username, and optional grants
 * @returns Object containing accessToken and optional refreshToken
 *
 */
export const createJwtTokens = (config: JwtConfig, user: User): JwtTokens => {
  // Default configuration values
  const secret = config.secret ?? "jwt_secret@auth";
  const accessExpiry = config.expiresIn ?? "8h";
  const refreshExpiry = config.refreshExpiresIn ?? "7d";

  // Create base payload with conditional grants inclusion
  const basePayload = {
    id: user.id,
    username: user.username,
    ...(user.grants?.length && { grants: user.grants }),
  };

  // Generate access token
  const accessToken = jwt.sign({ ...basePayload, type: "access" }, secret, {
    expiresIn: accessExpiry,
  });

  // Early return if refresh token not requested
  if (!config.refresh) {
    return { accessToken };
  }

  // Generate refresh token with longer expiration
  const refreshToken = jwt.sign({ ...basePayload, type: "refresh" }, secret, {
    expiresIn: refreshExpiry,
  });

  return { accessToken, refreshToken };
};
