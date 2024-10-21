const express = require('express');
const passport = require('passport');
const {findUser} = require('../controllers/users-controller.js');
const { protectedRoute } = require('../controllers/users-controller');


const router = express.Router();

// const users = [
//     {
//         userName: 'ansad',
//         password: '1234'
//     },
//     {
//         userName: 'admin',
//         password: 'admin'
//     }
// ]
router.post('/login', findUser)
router.get('/protected', passport.authenticate('jwt', { session: false }), protectedRoute);


module.exports = router;