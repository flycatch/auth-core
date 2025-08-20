import { Request, Response, Router } from "express";
import { Config } from "../interfaces/config.interface";
import apiResponse from "../utils/api-response";
import createLogger from "../lib/wintson.logger";
import { createJwtTokens } from "../utils/jwt";
import { createSessionPayload } from "../utils/session";
import twoFactorAuth, {
  InvalidOtpError,
  OtpExpiredError,
  TransportNotFoundError,
} from "../utils/two-factor-auth";

export default (router: Router, config: Config) => {
  //Importing verifyOTP from
  const { verifyOtp, initiate2fa } = twoFactorAuth(config.twoFA);

  const logger = createLogger(config);

  router.post(
    `${config.twoFA?.prefix ? config.twoFA.prefix : "/auth/2fa"}/send-otp`,
    async (req: Request, res: Response) => {
      try {
        if (!config.twoFA || !config.twoFA.enabled) {
          throw new Error("Two Factor Authentication is not enabled");
        }

        const { email } = req.body;
        if (!email) {
          return res
            .status(400)
            .json({ message: "email required on request payload" });
        }

        const user = await config.userService.loadUser(email);
        if (!user) {
          logger.warn(`Invalid payload`);
          return res.status(404).json({ message: "Invalid Username" });
        }

        if (!user.is2faEnabled) {
          logger.warn("Two Factor Authentication is not enabled for the user");
          return res.status(403).json({
            error: "Two Factor Authentication is not enabled for the user",
          });
        }

        await initiate2fa(user);
        logger.info(`OTP Generated and transported succesfully`);
        res.status(200).json({
          message: "Send One Time Password for Two Factor Authentication",
        });
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
      } catch (error: any) {
        if (error instanceof TransportNotFoundError) {
          logger.warn(error.message);
          return res
            .status(500)
            .json({ error: "OTP generated, but No Transport Available" });
        }
        logger.error(`Two Factor Auth initalization Failed: ${error.message}`);
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
      if (!otp || !email) {
        return res.status(400).json({
          error: "Both 'otp' and 'email' are required in the request payload.",
        });
      }

      try {
        const user = await config.userService.loadUser(email);
        if (!user) {
          return res.status(401).json({ error: "Invalid User" });
        }

        const isValid = await verifyOtp(user, otp);
        if (!isValid) {
          res.status(401).json({ error: "Invalid OTP" });
        }

        logger.info("OTP Verified Successfully");
        // Issue JWT or session
        if (config.jwt?.enabled) {
          const tokens = createJwtTokens(config.jwt, user);

          logger.info(`JWT Login Succesful`);
          res.json(
            apiResponse(201, "Two Factor Oath Successfull", true, [tokens])
          );
        } else if (config.session?.enabled) {
          const payload = createSessionPayload(user);
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
        if (error instanceof OtpExpiredError || InvalidOtpError) {
          logger.warn(error.message);
          return res.status(400).json({ error: error.message });
        }
        logger.error(error.message);
        res.status(500).json({ error: error.message });
      }
    }
  );
};
