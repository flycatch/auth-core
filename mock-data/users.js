const bcrypt = require('bcryptjs');

// Mock user database
const users = [
  {
    id: 1,
    username: 'john',
    password: bcrypt.hashSync('password123', 10), // Hashed password
  },
  {
    id: 2,
    username: 'jane',
    password: bcrypt.hashSync('password456', 10),
  }
];

module.exports = users;
