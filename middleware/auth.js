// server/middleware/auth.js
const jwt = require('jsonwebtoken');
const env = require('../config/env');

const authenticateToken = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ message: 'No token provided' });

  try {
    const decoded = jwt.verify(token, env.JWT_SECRET);
    req.user = { userId: decoded.userId };
    next();
  } catch (error) {
    console.error('Error:', error.message);
    return res.status(403).json({ message: 'Invalid token' });
  }
};

module.exports = authenticateToken;