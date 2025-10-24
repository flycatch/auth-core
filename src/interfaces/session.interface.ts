/**
 * Represents the payload stored in a session for an authenticated user.
 *
 * Contains basic user identification, session type, and optional role/grant information.
 */
export interface SessionPayload {
  id: string | number;
  username: string;
  type: "access";
  grants?: (string | number)[];
}
