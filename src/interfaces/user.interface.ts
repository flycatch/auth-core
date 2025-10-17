/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * Represents a generic user in the system.
 */
export interface User {
  id: string | number;
  email: string;
  username: string;
  grants?: (string | number)[];
  [key: string]: any;
}

/**
 * Represents a user profile obtained from an OAuth provider.
 */
export interface OAuthUserProfile {
  provider: string;
  providerId: string;
  username: string;
  email: string;
  login?: string;
  attributes: Record<string, any>;
}

/**
 * Represents the result of user provisioning after OAuth login or account creation.
 */
export interface UserProvisionResult {
  user: User;
  authorities?: string[];
}
