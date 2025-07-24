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
  secret: string;
  expiresIn?: `${number}${"s" | "m" | "h" | "d" | "w" | "y"}` | number;
  refresh?: boolean;
  prefix?: string;
}

interface GoogleConfig {
  enabled: boolean;
  clientID: string;
  clientSecret: string;
  callbackURL: string;
  secret: string;
}

export default interface Config {
  jwt?: JwtConfig;
  session?: SessionConfig;
  google?: GoogleConfig;
  userService: {
    loadUser: (email: string) => Promise<any>;
  };
  passwordChecker: (
    inputPassword: string,
    storedPassword: string
  ) => Promise<boolean>;
}
