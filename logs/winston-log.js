const { createLogger, format, transports } = require('winston');

// Create Winston logger
const logger = createLogger({
    level: 'debug', // Set the minimum level to 'debug' (includes info, warn, error, etc.)
    format: format.combine(
        format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }), // Timestamp formatting
        format.printf(({ timestamp, level, message }) => `${timestamp} [${level}]: ${message}`)
    ),
    transports: [
        // Log to the console for all levels
        new transports.Console({
            level: 'debug', // Capture all logs starting from 'debug' level and higher
        }),
        // Log all levels to the file
        new transports.File({
            filename: 'logs/passport.log',
            level: 'debug', // Capture all levels starting from 'debug'
        }),
        // You can also add more transports if needed (e.g., sending logs to external systems)
    ],
});

module.exports = logger;
