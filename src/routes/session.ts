import Config from "../interfaces/config.interface";
import logger from "../lib/wintson.logger";
import express, { Request, Response, Router } from "express";

// Extend express-session types to include 'user'
declare module "express-session" {
  interface SessionData {
    user?: { username: string };
  }
}

export default (router: Router, config: Config) => {
  router.use(express.json());
  const prefix = config.session?.prefix || "/auth/session";

  //Login Route
  router.post(`${prefix}/login`, async (req: Request, res: Response) => {
    const { username, password } = req.body;

    logger.info(` session login attempt for username: ${username}`);
    try {
      const user = await config.userService.loadUser(username);
      if (!user) {
        logger.warn(`Login failed: User not found (username ${username})`);
        return res.status(401).json({ error: "Invalid username or password" });
      }

      const validPassword = await config.passwordChecker(
        password,
        user.password
      );
      if (!validPassword) {
        logger.warn(`Login failed: invalid password`);
        return res.status(401).json({ error: "Invalid username or password" });
      }

      // Store user details in session
      req.session.user = { username: user.username };

      logger.info(`session Login successfull for username: ${username}`);
      res.status(200).json({ message: "Login Successfull" });
    } catch (error) {
      logger.error(`session Login error for username ${username} `, error);
      res.status(500).json({ error: "Internal server error" });
    }
  });
};
