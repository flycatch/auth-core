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
}

// Function-based approach
declare function auth(config: Config): Router;
declare function setupSession(config: Config, router: Router): void;
declare function setupGoogleAuth(config: Config): void;
declare function verify(): (req: any, res: any, next: any) => void;

// Exporting individual functions
export { auth, setupSession, setupGoogleAuth, verify };










// // AuthCore.d.ts

// import { Router } from "express";

// interface SessionConfig {
//     enabled: boolean;
//     secret?: string;
//     prefix?: string;
//     resave?: boolean;
//     saveUninitialized?: boolean;
//     cookie?: {
//         secure?: boolean;
//         maxAge?: number;
//     };
// }

// interface JwtConfig {
//     enabled: boolean;
//     secret: string;
//     expiresIn?: string;
//     refresh?: boolean;
//     prefix?: string;
// }

// interface GoogleConfig {
//     enabled: boolean;
//     clientID: string;
//     clientSecret: string;
//     callbackURL: string;
//     secret: string;
// }

// interface Config {
//     jwt?: JwtConfig;
//     session?: SessionConfig;
//     google?: GoogleConfig;
//     user_service: {
//         load_user: (email: string) => Promise<any>; 
//     };
//     password_checker: (inputPassword: string, storedPassword: string) => Promise<boolean>; // Added password_checker
// }

// declare class AuthCore {
//     private configurations: Config;
//     public router: Router;

//     constructor();

//     config(config: Config): Router;

//     private setupSession(config: Config): void;

//     private setupGoogleOath(config: Config): void;

//     public verify(): (req: any, res: any, next: any) => void;
// }

// // Exporting a default instance of AuthCore
// declare const authCore: AuthCore;

// export default authCore;