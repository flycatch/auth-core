const express = require('express');
const cors = require('cors');
const passport = require('passport');
const { findUser, protectedRoute } = require('./controllers/users-controller');
require('./middleware/passport'); // Passport configuration


const app = express();

app.use(express.json())
app.use(express.urlencoded({extended: true}));
app.use(cors());
app.use(passport.initialize()); // Initialize Passport


// app.use('/auth', router);

app.post('/login', findUser)
app.get('/protected', passport.authenticate('jwt', { session: false }), protectedRoute);

app.listen(5000, (req, res) => {
    console.log('listening to the port 5000');
})