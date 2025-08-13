interface SessionConfig {
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

interface JwtConfig {
  enabled: boolean;
  secret?: string;
  expiresIn?: `${number}${"s" | "m" | "h" | "d" | "w" | "y"}` | number;
  refresh?: boolean;
  prefix?: string;
}

interface GoogleConfig {
  enabled: boolean;
  clientID: string;
  clientSecret: string;
  prefix?: string;
}

interface TwoFAConfig {
  enabled: boolean;
  otpLength: number;
  otpExpiresIn: number;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  transport: (otp: string, user: any) => Promise<void>;
  storeOtp: (userId: string, otp: string, expiresInMs: string) => Promise<void>;
  getStoredOtp: (userId: string) => Promise<string | null>;
  clearOtp: (userId: string) => Promise<void>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  onOtpGenerated?: (otp: string, user: any) => Promise<void>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  onOtpSent?: (user: any) => Promise<void>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  onVerifySuccess?: (user: any) => Promise<void>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  onVerifyFail?: (user: any, error: any) => Promise<void>;
}

export interface Config {
  jwt?: JwtConfig;
  session?: SessionConfig;
  google?: GoogleConfig;
  twoFA?: TwoFAConfig;
  userService: {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    loadUser: (email: string) => Promise<any>;
  };
  passwordChecker: (
    inputPassword: string,
    storedPassword: string
  ) => Promise<boolean>;
  logs: boolean;
}
