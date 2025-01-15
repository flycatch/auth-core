const jwt = require('jsonwebtoken');

// Secret for JWT
const jwtSecret = 'jwt-secret-key';

// Function to generate a JWT token
function generateJwt(user) {
  const payload = {
    id: user.id,
    username: user.username,
  };
  return jwt.sign(payload, jwtSecret, { expiresIn: '1h' });
}

module.exports = {
  jwtSecret,
  generateJwt,
};
