import winston from "winston";
import { Config } from "../interfaces/config.interface";

const { combine, timestamp, printf, colorize, align } = winston.format;

/**
 * Creates and configures a Winston logger instance based on the provided configuration.
 *
 * The logger supports colorized output, timestamps, and aligned formatting.
 * Log level is determined by the `logs` flag in the configuration:
 * - If `config.logs` is true, log level is "info".
 * - Otherwise, log level is "warn".
 *
 * @param {Config} config - Application configuration object containing logging settings.
 * @returns {winston.Logger} Configured Winston logger instance.
 */
const createLogger = (config: Config): winston.Logger => {
  const logLevel = config?.logs ? "info" : "warn";

  return winston.createLogger({
    level: logLevel,
    format: combine(
      colorize({ all: true }),
      timestamp({ format: "YYYY-MM-DD hh:mm:ss.SSS A" }),
      align(),
      printf((info) => `[${info.timestamp}] ${info.level}: ${info.message}`)
    ),
    transports: [new winston.transports.Console()],
  });
};

export default createLogger;
