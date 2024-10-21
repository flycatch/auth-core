// logger.js (Utility to set up Winston logging)
const { createLogger, format, transports } = require('winston');

const logger = createLogger({
    level: 'info', // Set the logging level (error, warn, info, verbose, debug, silly)
    format: format.combine(
        format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        format.printf(({ timestamp, level, message }) => `${timestamp} [${level}]: ${message}`)
    ),
    transports: [
        new transports.Console(), // Log to the console
        new transports.File({ filename: 'logs/passport.log' }) // Log to a file
    ],
});

module.exports = logger;
