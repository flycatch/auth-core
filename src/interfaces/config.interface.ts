/* eslint-disable @typescript-eslint/no-explicit-any */
import { User } from "./user.interface";

export interface SessionConfig {
  enabled: boolean;
  secret?: string;
  prefix?: string;
  resave?: boolean;
  saveUninitialized?: boolean;
  cookie?: {
    secure?: boolean;
    maxAge?: number;
  };
}

type expiresIn = `${number}${"s" | "m" | "h" | "d" | "w" | "y"}` | number;
export interface JwtConfig {
  enabled: boolean;
  secret?: string;
  expiresIn?: expiresIn;
  refresh?: boolean;
  refreshExpiresIn?: expiresIn;
  prefix?: string;
}

export interface TwoFAConfig {
  enabled: boolean;
  otpLength?: number;
  otpExpiresIn?: expiresIn;
  prefix?: string;
  transport?: (otp: string, user: User) => Promise<void>;
  storeOtp?: (
    userId: string | number,
    otp: string,
    expiresInMs: number
  ) => Promise<void>;
  getStoredOtp?: (userId: string | number) => Promise<string | null>;
  clearOtp?: (userId: string | number) => Promise<void>;
  onOtpGenerated?: (otp: string, user: User) => Promise<void>;
  onOtpSent?: (user: User) => Promise<void>;
  onVerifySuccess?: (user: User) => Promise<void>;
  onVerifyFail?: (user: User, error: any) => Promise<void>;
}

// OAuth 2.0 Configuration Interface (OAuth 2.0 only)
export type OAuth2Providers = "google" | "facebook" | "github" | "twitter";

export interface BaseProviderConfig {
  clientID: string;
  clientSecret: string;
  callbackURL?: string;
  scope?: string[];
}

export interface CustomProviderConfig extends BaseProviderConfig {
  // Strategy class or constructor function for OAuth 2.0
  strategy: any;
  // Custom configuration specific to the provider
  customConfig?: Record<string, any>;
  // Custom profile field mappings
  profileMapping?: {
    email?: string; // path to email in profile
    id?: string; // path to user id in profile
    name?: string; // path to name in profile
  };
  // Custom verify callback for OAuth 2.0
  customVerifyCallback?: (
    accessToken: string,
    refreshToken: string,
    profile: any,
    done: (error: any, user?: any, info?: any) => void
  ) => void;
}

export interface OAuth2Config {
  enabled: boolean;
  baseURL?: string;
  prefix?: string;
  providers: {
    [key in OAuth2Providers]?: BaseProviderConfig;
  };
  // Global custom providers configuration
  customProviders?: {
    [providerName: string]: CustomProviderConfig;
  };
}

export interface Config {
  jwt?: JwtConfig;
  session?: SessionConfig;
  twoFA?: TwoFAConfig;
  oauth?: OAuth2Config;
  userService: {
    loadUser: (email: string) => Promise<User | null | undefined>;
  };
  passwordChecker: (
    inputPassword: string,
    storedPassword: string
  ) => Promise<boolean>;
  logs: boolean;
}
