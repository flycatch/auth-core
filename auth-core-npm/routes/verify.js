const jwt = require('jsonwebtoken');
const logger = require('../lib/wintson.logger');

module.exports = (config) => (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
        logger.warn('Unauthorized access attempt: Missing token');
        return res.status(401).json({ error: 'Unauthorized' });
    }

    jwt.verify(token, config.jwt.secret, (err, user) => {
        if (err) {
            logger.warn('Invalid or expired token', { error: err.message });
            return res.status(403).json({ error: 'Token is invalid or expired' });
        }

        logger.info(`Token verified successfully for username: ${user.username}`);
        req.user = user;
        next();
    });
};
