import { Request, Response, Router } from "express";
import { Config } from "../interfaces/config.interface";
import { create2faHandlers } from "../config/two-factor-auth.config";
import jwt from "jsonwebtoken";
import apiResponse from "../utils/api-response";
import createLogger from "../lib/wintson.logger";

export default (router: Router, config: Config) => {
  //Importing verifyOTP from
  const { verifyOtp, initiate2fa } = create2faHandlers(config);

  const logger = createLogger(config);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const createAccessToken = async (user: any) => {
    const payload = {
      id: user.id,
      username: user.username,
      type: "access",
      ...(user.grands && user.grands.length > 0 && { grands: user.grands }), // Add only if user.grands exists and is not empty
    };

    if (!config.jwt || !config.jwt.secret) {
      throw new Error("JWT configuration is missing or incomplete.");
    }

    const accessToken = jwt.sign(payload, config.jwt.secret, {
      expiresIn: config.jwt.expiresIn || "8h",
    });
    return accessToken;
  };

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const createRefreshToken = async (user: any) => {
    const payload = {
      id: user.id,
      username: user.username,
      type: "refresh",
      ...(user.grands && user.grands.length > 0 && { grands: user.grands }), // Add only if user.grands exists and is not empty
    };

    if (!config.jwt || !config.jwt.secret) {
      throw new Error("JWT configuration is missing or incomplete.");
    }
    const refreshToken = jwt.sign(payload, config.jwt.secret, {
      expiresIn: "7d",
    });
    return refreshToken;
  };

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const createSessionPayload = (user: any) => {
    return {
      id: user.id,
      username: user.username,
      type: "access",
      ...(user.grands && user.grands.length > 0 && { grands: user.grands }), // Add only if user.grands exists and is not empty
    };
  };

  router.post(
    `${config.twoFA?.prefix ? config.twoFA.prefix : "/auth/2fa"}/send-otp`,
    async (req: Request, res: Response) => {
      const { email } = req.body;
      const user = await config.userService.loadUser(email);
      try {
        console.log("Hi")
        await initiate2fa(user);
        logger.info(`OTP Generated and transported succesfully`);
        res.status(200).json({
          message: "Send One Time Password for Two Factor Authentication",
        });
      } catch (error) {
        logger.error(`Two Factor Auth initalization Failed: ${error}`);
        res.status(500).json({
          error: "Two Factor Auth initalization Failed",
        });
      }
    }
  );

  router.post(
    `${config.twoFA?.prefix ? config.twoFA.prefix : "/auth/2fa"}/verify`,
    async (req: Request, res: Response) => {
      const { otp, email } = req.body;
      const user = await config.userService.loadUser(email);
      try {
        const isValid = await verifyOtp(user, otp);
        if (!isValid) {
          res.status(401).json({ error: "Invalid OTP" });
        }
        logger.info("OTP Verified Successfully");
        // Issue JWT or session
        if (config.jwt?.enabled) {
          try {
            const accessToken = await createAccessToken(req.user);
            const refreshToken = await createRefreshToken(req.user);
            res.json(
              apiResponse(201, "Two Factor Oath Successfull", true, [
                accessToken,
                refreshToken,
              ])
            );
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
          } catch (err: any) {
            logger.error("Error during 2FA Token Generation", {
              error: err.message,
              stack: err.stack,
            });
            res
              .status(500)
              .json(apiResponse(500, "Internal server error", false));
          }
        } else if (config.session?.enabled) {
          const payload = createSessionPayload(req.user);
          // Store user details in session
          req.session.user = payload;

          logger.info(`session Login successfull `);
          return res.json(
            apiResponse(201, "Login Successfull", true, [payload])
          );
        } else {
          logger.error(
            "Either Jwt or Session should be configured to get tokens from google OAuth"
          );
          res.status(500).json({
            error: "Either JWT or Session auth configured to use google OAuth",
          });
        }
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      } catch (error: any) {
        res.status(400).json({ error: error.message });
      }
    }
  );
};
