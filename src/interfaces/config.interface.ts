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

export interface GoogleConfig {
  enabled: boolean;
  clientID: string;
  clientSecret: string;
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
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  onVerifyFail?: (user: User, error: any) => Promise<void>;
}

type OAuth2Providers = "google" | "facebook" | "twitter" | "github";

export interface OAuth2Config {
  enabled: boolean;
  providers: {
    [key in OAuth2Providers]?: {
      clientID: string;
      clientSecret: string;
      callbackURL?: string;
      scope?: string[];
    };
  };
  prefix?: string;
}

export interface Config {
  jwt?: JwtConfig;
  session?: SessionConfig;
  google?: GoogleConfig;
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
