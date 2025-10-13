export interface User {
  id: string | number;
  email: string;
  username: string;
  grants?: (string | number)[];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [key: string]: any;
}

export interface OAuthUserProfile {
  provider: string;
  providerId: string;
  username: string;
  email: string;
  login?: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  attributes: Record<string, any>;
}

export interface UserProvisionResult {
  user: User;
  authorities?: string[];
}
