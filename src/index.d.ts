import { Router } from "express";

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
    expiresIn?: string;
    refresh?: boolean;
    prefix?: string;
}

interface GoogleConfig {
    enabled: boolean;
    clientID: string;
    clientSecret: string;
    callbackURL: string;
    secret?: string;
}

interface Config {
    jwt?: JwtConfig;
    session?: SessionConfig;
    google?: GoogleConfig;
    user_service: {
        load_user: (email: string) => Promise<any>;
    };
    password_checker: (inputPassword: string, storedPassword: string) => Promise<boolean>;
    logs: boolean;
}

// Function-based approach
declare function config(config: Config): Router;
declare function setupSession(config: Config, router: Router): void;
declare function setupGoogleAuth(config: Config): void;
declare function verify(permission?: string): (req: any, res: any, next: any) => void;

// Exporting individual functions
export { config, setupSession, setupGoogleAuth, verify };
