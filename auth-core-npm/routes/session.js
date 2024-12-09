const logger = require('../lib/wintson.logger');

module.exports = (router, config) => {
    const prefix = config.session.prefix || '/auth/session';

    //Login Route
    router.post(`${prefix}/login`, async (req, res) => {
        const { username, password } = req.body;

        logger.info(` session login attempt for username: ${username}`);
        try {

            const user = await config.user_service.load_user(username);
            console.log(user);
            if (!user) {
                logger.warn(`Login failed: User not found (username ${username})`);
                res.status(401).json({ error: 'Invalid username or password'});
            }
            
            const validPassword = await config.password_checker(password, user.password);
            console.log(validPassword);
            if (!validPassword) {
                logger.warn(`Login failed: invalid password`);
                res.status(401).json({ error: 'Invalid username or password'})
            }

            // Store user details in session
            req.session.user = { username: user.username };
           
            logger.info(`session Login successfull for username: ${username}`);
            res.json({message: 'Login Successfull'});
        }
        catch(error) {
            logger.error(`session Login error for username ${username} `, error );
            res.status(500).json({ error: 'Internal server error' });
        }
    })
}