const winston = require('winston');
const { combine, timestamp, printf, colorize, align } = winston.format;

// Function to create a logger based on config
const createLogger = (config) => {
  const logLevel = config?.logs ? 'info' : 'warn'; // Allow 'info' logs if enabled, otherwise only 'warn' logs.

  return winston.createLogger({
    level: logLevel,
    format: combine(
      colorize({ all: true }),
      timestamp({ format: 'YYYY-MM-DD hh:mm:ss.SSS A' }),
      align(),
      printf((info) => `[${info.timestamp}] ${info.level}: ${info.message}`)
    ),
    transports: [new winston.transports.Console()],
  });
};

module.exports = createLogger;

