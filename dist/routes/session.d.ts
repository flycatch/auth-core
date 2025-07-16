import Config from "../interfaces/config.interface";
import { Router } from "express";
declare module "express-session" {
    interface SessionData {
        user?: {
            username: string;
        };
    }
}
declare const _default: (router: Router, config: Config) => void;
export default _default;
