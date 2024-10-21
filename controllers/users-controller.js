const jwt = require('jsonwebtoken');


const users = [
    { username: 'admin', password: 1234, id: 1 },
    { username: 'ramu', password: 1234, id: 12 },
    { username: 'anu', password: 1234, id: 123 }
  ];

// Login and issue JWT
const findUser =  (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    // console.log(users.find(u=> u.username === username));

    const user = users.find(user => user.username === username );
    console.log(user);
    if (user) {

        const payload = {
            username: user.username,
            id: user.id
        }
        
        const token = jwt.sign(payload, 'jwtsecret', {expiresIn: "1d"});

       return res.status(200).send({
            success: true,
            message: 'logged successfully',
            token: `Bearer ${token}`
        })
    }
    return res.status(401).send({
        success: false,
        message: 'could not find user or credentials not matched'
    })
} 


const protectedRoute = (req, res) => {
    // The user object is available on req.user due to passport
    // This object contains the information from the JWT payload
    const user = req.user;

    return res.status(200).json({
        success: true,
        message: 'This is a protected route',
        user: {
            username: user.username, // This is the username from the JWT payload
            id: user.id              // This is the user ID from the JWT payload
        }
    });
};

module.exports = {findUser, protectedRoute};
