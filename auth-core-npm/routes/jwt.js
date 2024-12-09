const jwt = require('jsonwebtoken');
const logger = require('../lib/wintson.logger');

module.exports = (router, config) => {
    const prefix = config.jwt.prefix || '/auth/jwt';

    // Login Route
    router.post(`${prefix}/login`, async (req, res) => {
        const { username, password } = req.body;

        logger.info(`Login attempt for username: ${username}`);
        try {
            const user = await config.user_service.load_user(username);
            if (!user) {
                logger.warn(`Login failed: User not found (username: ${username})`);
                return res.status(401).json({ error: 'Invalid username or password' });
            }

            const isValidPassword = await config.password_checker(password, user.password);
            if (!isValidPassword) {
                logger.warn(`Login failed: Incorrect password (username: ${username})`);
                return res.status(401).json({ error: 'Invalid username or password' });
            }

            const payload = {
                id: user.id,
                username: user.username
            }

            const accessToken = jwt.sign(
                payload,
                config.jwt.secret,
                { expiresIn: config.jwt.jwt_expires || '8h' }
            );
            const refreshToken = config.jwt.refresh
                ? jwt.sign({ username: user.username }, config.jwt.secret, { expiresIn: '7d' })
                : null;

            logger.info(`Login successful for username: ${username}`);
            res.json({ accessToken, refreshToken });
        } catch (error) {
            logger.error(`JWT Login Error for username: ${username}`, { error });
            res.status(500).json({ error: 'Internal Server Error' });
        }
    });

    // Refresh Token Route
    if (config.jwt.refresh) { 
        router.post(`${prefix}/refresh`, (req, res) => {
            const { refreshToken } = req.body;

            logger.info(`Refresh token attempt received`);
            if (!refreshToken) {
                logger.warn('Refresh token missing in request');
                return res.status(400).json({ error: 'Refresh token is required' });
            }

            try {
                jwt.verify(refreshToken, config.jwt.secret, (err, user) => {
                    if (err) {
                        logger.warn('Invalid refresh token provided', { error: err.message });
                        return res.status(403).json({ error: 'Invalid refresh token' });
                    }

                    const accessToken = jwt.sign(
                        { username: user.username },
                        config.jwt.secret,
                        { expiresIn: config.jwt.jwt_expires ||'8h' }
                    );

                    logger.info(`Access token refreshed for username: ${user.username}`);
                    res.json({ accessToken });
                });
            } catch (error) {
                logger.error('JWT Refresh Error', { error });
                res.status(500).json({ error: 'Internal Server Error' });
            }
        });
    }
};
