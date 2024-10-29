const { createLogger, format, transports } = require('winston');

const logger = createLogger({
  level: 'debug', // Minimum log level to capture (debug, info, warn, error)
  format: format.combine(
    format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    format.printf(({ timestamp, level, message }) => `${timestamp} [${level.toUpperCase()}]: ${message}`)
  ),
  transports: [
    new transports.Console(),
    new transports.File({ filename: 'application.log' })
  ],
});

module.exports = logger;
