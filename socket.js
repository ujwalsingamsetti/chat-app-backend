// server/socket.js
const jwt = require('jsonwebtoken');
const env = require('./config/env');
const User = require('./models/User');
const Message = require('./models/Message');

const setupSocket = (io) => {
  io.on('connection', (socket) => {
    console.log('User connected:', socket.id);

    const token = socket.handshake.auth.token;
    if (!token) {
      socket.emit('connect_error', { message: 'Authentication error: No token provided' });
      socket.disconnect();
      return;
    }

    let user;
    try {
      const decoded = jwt.verify(token, env.JWT_SECRET);
      User.findById(decoded.userId).then((foundUser) => {
        if (!foundUser) throw new Error('User not found');
        user = foundUser;
        socket.username = user.username;

        io.emit('onlineUsers', Array.from(io.sockets.sockets).map(([id, s]) => ({
          id,
          username: s.username,
        })));
      }).catch((error) => {
        console.error('Socket authentication error:', error);
        socket.emit('connect_error', { message: 'Authentication error: Invalid token' });
        socket.disconnect();
      });
    } catch (error) {
      console.error('Socket authentication error:', error);
      socket.emit('connect_error', { message: 'Authentication error: Invalid token' });
      socket.disconnect();
      return;
    }

    socket.on('disconnect', () => {
      console.log('User disconnected:', socket.id);
      io.emit('onlineUsers', Array.from(io.sockets.sockets).map(([id, s]) => ({
        id,
        username: s.username,
      })));
    });

    socket.on('sendMessage', async (data) => {
      try {
        const message = new Message({
          username: user.username,
          message: data.message,
          recipientId: data.recipientId || null,
        });
        await message.save();
        io.emit('newMessage', { ...message._doc, id: message._id });
      } catch (error) {
        console.error('Error sending message:', error);
      }
    });

    socket.on('react', async (data) => {
      try {
        const message = await Message.findById(data.messageId);
        if (message) {
          message.reactions.push({ username: user.username, reaction: data.reaction });
          await message.save();
          io.emit('newReaction', { messageId: data.messageId, username: user.username, reaction: data.reaction });
        }
      } catch (error) {
        console.error('Error adding reaction:', error);
      }
    });

    socket.on('typing', () => {
      socket.broadcast.emit('typing', user.username);
    });

    socket.on('stopTyping', () => {
      socket.broadcast.emit('stopTyping');
    });
  });
};

module.exports = setupSocket;