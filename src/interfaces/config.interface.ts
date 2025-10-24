/* eslint-disable @typescript-eslint/no-explicit-any */
import { OAuth2Providers } from "./oauth2.type";
import { OAuthUserProfile, User } from "./user.interface";

/**
 * Configuration options for Express session management.
 */
export interface SessionConfig {
  enabled: boolean;
  secret?: string;
  prefix?: string;
  resave?: boolean;
  saveUninitialized?: boolean;
  cookie?: {
    secure?: boolean; // Indicates if cookies should be sent only over HTTPS
    maxAge?: number; // Maximum age of the cookie in milliseconds
  };
}

/**
 * Supported expiration formats for JWT tokens.
 * Accepts a number (milliseconds) or a string (e.g., "15m", "1h", "7d").
 */
type expiresIn = `${number}${"s" | "m" | "h" | "d" | "w" | "y"}` | number;

/**
 * Configuration for JWT authentication and token handling.
 */
export interface JwtConfig {
  enabled: boolean;
  secret?: string; // Secret key for signing JWT tokens
  expiresIn?: expiresIn; // Access token expiry time
  refresh?: boolean; // Whether to enable refresh token generation
  refreshExpiresIn?: expiresIn; // Refresh token expiry time
  prefix?: string; // Optional token prefix (e.g., 'Bearer')

  // Enhanced logout and security options
  revokeOnRefresh?: boolean; // Whether to blacklist refresh token when creating new tokens
  tokenBlacklist?: {
    // Token blacklist configuration - OPTIONAL
    enabled?: boolean; // If false or undefined, logout will be client-side only
    storageService?: {
      add: (token: string, expiresAt?: Date) => Promise<void> | void; // Add token to blacklist
      has: (token: string) => Promise<boolean> | boolean; // Check if token is blacklisted
      remove: (token: string) => Promise<void> | void; // Remove token from blacklist
      clear: () => Promise<void> | void; // Clear all blacklisted tokens
    };
    // Callback when user logs out of all sessions (for custom cleanup)
    onLogoutAll?: (userId: string | number) => Promise<void> | void;
  };
}

/**
 * Configuration for Two-Factor Authentication (2FA) using OTP.
 */
export interface TwoFAConfig {
  enabled: boolean; // Enable or disable 2FA
  otpLength?: number; // Length of the generated OTP
  otpType?: "numeric" | "alphanumeric"; // Type of OTP to generate
  otpExpiresIn?: expiresIn; // Expiration duration of OTP
  transport?: (otp: string, user: User) => Promise<void>; // Method to send OTP to user
  storeOtp: (
    userId: string | number,
    otp: string,
    expiresInMs: number
  ) => Promise<void>; // Method to store OTP
  getStoredOtp: (userId: string | number) => Promise<string | null>; // Retrieve stored OTP
  clearOtp?: (userId: string | number) => Promise<void>; // Clear OTP after verification
  onOtpGenerated?: (otp: string, user: User) => Promise<void>; // Callback after OTP generation
  onOtpSent?: (user: User) => Promise<void>; // Callback after OTP is sent
  onVerifySuccess?: (user: User) => Promise<void>; // Callback on successful OTP verification
  onVerifyFail?: (user: User, error: any) => Promise<void>; // Callback on OTP verification failure
}

/**
 * Configuration for an individual OAuth 2.0 provider.
 */
export interface ProviderConfig {
  clientID: string; // OAuth2 client ID
  clientSecret: string; // OAuth2 client secret
  callbackURL?: string; // Callback URL for OAuth2 redirect
  scope?: string[]; // Scopes requested from the provider

  // Strategy class or constructor function for OAuth 2.0
  strategy: any;

  // Custom configuration specific to the provider
  customConfig?: Record<string, any>;

  // Custom profile field mappings
  profileMapping?: {
    email?: string; // Path to email in profile
    id?: string; // Path to user id in profile
    name?: string; // Path to name in profile
  };

  // to customize callBack
  customVerifyCallback?: (
    accessToken: string,
    refreshToken: string,
    profile: any,
    done: (error: any, user?: any, info?: any) => void
  ) => void;
}


/**
 * Information provided to OAuth2 callbacks
 */
export interface OAuth2CallbackInfo {
  provider: string;
  profile: OAuthUserProfile;
  accessToken: string;
  refreshToken: string;
  existingUser?: User | null;
}

/**
 * Global configuration for OAuth 2.0 authentication.
 */
export interface OAuth2Config {
  refreshTokenParam: string; // Query parameter name for refresh token
  accessTokenParam: string; // Query parameter name for access token
  enabled: boolean; // Whether OAuth2 is enabled
  baseURL?: string; // Base URL for OAuth2 callback routes
  prefix?: string; // API prefix for OAuth2 routes
  successRedirect: string; // Redirect URL on successful login
  failureRedirect: string; // Redirect URL on failed login
  defaultRole?: string; // Default role assigned to new users
  setRefreshCookie?: boolean; // Store refresh token as an HTTP cookie
  appendTokensInRedirect?: boolean; // Append tokens in redirect URL
  includeAuthorities?: boolean; // Include roles/grants in tokens
  issueJwt?: boolean; // Whether to issue JWT tokens

   /**
   * Callback executed on successful OAuth2 authentication
   * This is where user registration/creation logic should be implemented
   * @param info - Contains provider details, user profile, and tokens
   * @returns User object (existing or newly created)
   */
  onSuccess?: (info: OAuth2CallbackInfo) => Promise<User> | User;

  /**
   * Callback executed on OAuth2 authentication failure
   * @param error - Error code
   * @param errorDescription - Detailed error description
   * @param provider - OAuth2 provider name
   */
  onFailure?: (
    error: string,
    errorDescription: string,
    provider: string
  ) => Promise<void> | void;

  // List of configured OAuth2 providers
  providers: {
    [key in OAuth2Providers]?: ProviderConfig;
  };
}

/**
 * Configuration for cookies used in authentication or sessions.
 */
export interface CookieConfig {
  enabled: boolean; // Enable or disable cookie-based auth
  name?: string; // Cookie name
  httpOnly?: boolean; // Prevent access to cookies via JavaScript
  secure?: boolean; // Send cookies only over HTTPS
  sameSite?: "Strict" | "Lax" | "None"; // Cookie SameSite policy
  maxAge?: number; // Cookie expiry time in milliseconds
  path?: string; // Cookie path
}

/**
 * Root application configuration interface combining
 * authentication, session, OAuth2, and related services.
 */
export interface Config {
  jwt?: JwtConfig; // JWT configuration
  session?: SessionConfig; // Session configuration
  twoFA?: TwoFAConfig; // Two-Factor Authentication configuration
  oauth2?: OAuth2Config; // OAuth 2.0 configuration
  cookies?: CookieConfig; // Cookie configuration

  // Service for loading and creating users
  userService: {
    loadUser: (email: string) => Promise<User | null | undefined>; // Fetch user by email
  };

  // Method to compare passwords
  passwordChecker: (
    inputPassword: string,
    storedPassword: string
  ) => Promise<boolean>;

  logs: boolean; // Enable or disable detailed logging
}
