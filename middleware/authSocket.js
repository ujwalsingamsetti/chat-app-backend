// server/middleware/authSocket.js
const jwt = require('jsonwebtoken');
const env = require('../config/env');

const authenticateSocket = (socket, next) => {
  console.log('Socket handshake auth:', socket.handshake.auth);
  const token = socket.handshake.auth.token;
  console.log('Extracted token for socket:', token);
  if (!token) {
    const error = new Error('Authentication error: No token provided');
    console.error(error.message);
    return next(error);
  }

  try {
    const decoded = jwt.verify(token, env.JWT_SECRET);
    socket.userId = decoded.userId;
    console.log('Socket authenticated, userId:', socket.userId);
    next();
  } catch (error) {
    console.error('Socket authentication error:', error.message);
    next(new Error('Authentication error: Invalid token'));
  }
};

module.exports = authenticateSocket;