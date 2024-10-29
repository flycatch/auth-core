const express = require('express');
const session = require('express-session');
const passport = require('passport');
const bodyParser = require('body-parser');
const logger = require('./libs/wintson-logger');
const routes = require('./routes/user.routes');
require('./middleware/passport'); // Load passport strategies

const app = express();

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Express session middleware for session-based auth
app.use(session({
  secret: 'session-secret-key',
  resave: false,
  saveUninitialized: false,
}));

// Initialize Passport and session handling
app.use(passport.initialize());
app.use(passport.session()); // For session-based auth

// Setup routes
app.use('/', routes);

const port = 3003;
app.listen(port, () => {
    logger.info(`Server is running on http://localhost:${port}`);
});
