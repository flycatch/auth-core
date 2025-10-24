import { SessionPayload } from "../interfaces/session.interface";
import { User } from "../interfaces/user.interface";

/**
 * Creates a session payload object for authentication.
 *
 * @param user - The user object used to generate the session payload.
 * @returns A session payload containing the user's id, username, type,
 *          and optionally the grants (if provided and non-empty).
 */
export const createSessionPayload = (user: User): SessionPayload => {
  return {
    id: user.id,
    username: user.username,
    type: "access",
    ...(user.grants && user.grants.length > 0 ? { grands: user.grants } : {}),
  };
};
