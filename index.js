// const express = require('express');
// const cors = require('cors');
// const passport = require('passport');
// const bodyParser = require('body-parser');
// const { findUser, protectedRoute } = require('./controllers/users-controller');
// require('./middleware/passport'); // Passport configuration

// const session = require('express-session');

// const app = express();

// app.use(session({
//   secret: 'session-key',
//   resave: true,
//   saveUninitialized: true,
//   cookie: { secure: true }
// }));

// // Middleware
// app.use(bodyParser.urlencoded({ extended: true }));
// app.use(bodyParser.json());

// // app.use(express.json())
// // app.use(express.urlencoded({extended: true}));
// app.use(cors());

// // app.use(session({
// //     secret: 'your-secret-key',  // Use a strong secret in production
// //     resave: false,
// //     saveUninitialized: false
// //   }));
// app.use(passport.initialize()); // Initialize Passport
// app.use(passport.session());  // Persistent login sessions


// // app.use('/auth', router);

// app.post('/login', findUser)
// app.get('/protected', passport.authenticate('jwt', { session: false }), protectedRoute);
// app.get('/sessionBasedPage', passport.authenticate('session'), (req, res) => {
//     res.send({message: 'session passed'}).status(201);
// })
// app.listen(5000, (req, res) => {
//     console.log('listening to the port 5000');
// })



const express = require('express');
const session = require('express-session');
const passport = require('passport');
const bodyParser = require('body-parser');
const routes = require('./routes/user.routes');
require('./middleware/passport'); // Load passport strategies

const app = express();

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Express session middleware for session-based auth
app.use(session({
  secret: 'your-secret-key',
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
  console.log(`Server running on http://localhost:${port}`);
});
