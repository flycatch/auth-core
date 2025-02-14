const logger = require('../lib/wintson.logger');
const express = require("express");

module.exports = (router, config) => {
    router.use(express.json()); 
    const prefix = config.session.prefix || '/auth/session';

    //Login Route
    router.post(`${prefix}/login`, async (req, res) => {
        const { username, password } = req.body;

        logger.info(` session login attempt `);
        try {

            const user = await config.user_service.load_user(username);
            if (!user) {
                logger.warn(`Login failed: User not found (username ${username})`);
                res.status(401).json({ error: 'Invalid username or password'});
            }
            
            const validPassword = await config.password_checker(password, user.password);
            if (!validPassword) {
                logger.warn(`Login failed: invalid password`);
                res.status(401).json({ error: 'Invalid username or password'})
            }
            const payload = {
                id: user.id,
                username: user.username,
                type: "access",
                ...(user.grands && user.grands.length > 0 && { grands: user.grands }) // Add only if user.grands exists and is not empty
              };
            // Store user details in session
            req.session.user = payload;
           
            logger.info(`session Login successfull `);
            res.json({message: 'Login Successfull'});
        }
        catch(error) {
            logger.error(`session Login error for username ${username} `, error );
            res.status(500).json({ error: 'Internal server error' });
        }
    })
}