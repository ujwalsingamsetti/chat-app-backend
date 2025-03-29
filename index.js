const express = require('express');
const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');
const mongoose = require('mongoose');
require('dotenv').config();

console.log('All environment variables:', process.env);
console.log('MONGODB_URI:', process.env.MONGODB_URI);
console.log('JWT_SECRET:', process.env.JWT_SECRET);

// Global error handling
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

const app = express();

// Middleware
// app.use(express.json()); // Uncommented for endpoints like /register and /login
app.use((req, res, next) => {
  console.log(`Received request: ${req.method} ${req.url}`);
  next();
});

// Root route
app.get('/', (req, res) => {
  console.log('Handling GET / request');
  res.status(200).send('Hello from the server!');
  console.log('Response sent: Hello from the server!');
});

// Connect to MongoDB
console.log('Attempting to connect to MongoDB with URI:', process.env.MONGODB_URI);
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// MongoDB Schemas
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String,
});
const messageSchema = new mongoose.Schema({
  userId: String,
  recipientId: String,
  message: String,
  timestamp: String,
});
const reactionSchema = new mongoose.Schema({
  messageId: String,
  userId: String,
  reaction: String,
  username: String,
});

const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);
const Reaction = mongoose.model('Reaction', reactionSchema);

// Initialize server
const server = require('http').createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    methods: ['GET', 'POST'],
    credentials: true,
  },
});

// Online users array (in-memory, consider Redis for production)
let onlineUsers = [];

// Middleware to verify JWT token for REST API
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
  if (!token) return res.status(401).json({ message: 'No token provided' });

  jwt.verify(token, process.env.JWT_SECRET || 'your_secret_key_here', (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Register endpoint
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password required' });
  }

  try {
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: 'Username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword });
    await user.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password required' });
  }

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ message: 'Invalid username or password' });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(400).json({ message: 'Invalid username or password' });
    }

    const token = jwt.sign(
      { id: user._id, username: user.username },
      process.env.JWT_SECRET || 'your_secret_key_here',
      { expiresIn: '1h' }
    );
    res.json({ token });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Fetch messages endpoint
app.get('/messages', authenticateToken, async (req, res) => {
  const { recipientId } = req.query;
  const userId = req.user.id;

  try {
    let query = { recipientId: null };
    if (recipientId) {
      query = {
        $or: [
          { userId: userId, recipientId },
          { userId: recipientId, recipientId: userId },
        ],
      };
    }

    const messages = await Message.find(query).lean();
    const messageIds = messages.map((m) => m._id.toString());

    const users = await User.find({ _id: { $in: messages.map((m) => m.userId) } }).lean();
    const userMap = users.reduce((acc, user) => {
      acc[user._id] = user.username;
      return acc;
    }, {});

    let reactions = [];
    if (messageIds.length > 0) {
      reactions = await Reaction.find({ messageId: { $in: messageIds } }).lean();
    }

    const messagesWithReactions = messages.map((message) => ({
      ...message,
      id: message._id.toString(),
      username: userMap[message.userId] || 'Unknown',
      reactions: reactions
        .filter((r) => r.messageId === message._id.toString())
        .map((r) => ({ ...r, messageId: r.messageId.toString() })),
    }));
    res.json(messagesWithReactions);
  } catch (err) {
    console.error('Fetch messages error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Socket.IO Logic
io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) {
    return next(new Error('Authentication error: No token provided'));
  }

  jwt.verify(token, process.env.JWT_SECRET || 'your_secret_key_here', (err, user) => {
    if (err) {
      return next(new Error('Authentication error: Invalid token'));
    }
    socket.user = user;
    next();
  });
});

io.on('connection', (socket) => {
  console.log('New user connected:', socket.id);

  // Add user to onlineUsers if not already present
  if (!onlineUsers.some((u) => u.id === socket.user.id)) {
    onlineUsers.push({ id: socket.user.id, username: socket.user.username });
    io.emit('onlineUsers', onlineUsers);
  }

  // Join user-specific room for private messaging
  socket.join(`user-${socket.user.id}`);

  socket.on('sendMessage', async ({ message, recipientId }) => {
    console.log(
      'Message received from',
      socket.user.username,
      'to',
      recipientId ? `user ${recipientId}` : 'public',
      ':',
      message
    );
    const timestamp = new Date().toISOString();
    try {
      const msg = new Message({
        userId: socket.user.id,
        recipientId: recipientId || null,
        message,
        timestamp,
      });
      await msg.save();

      const msgData = {
        id: msg._id.toString(),
        username: socket.user.username,
        message,
        recipientId,
        timestamp,
        reactions: [],
      };
      console.log('Emitting newMessage:', msgData);
      if (recipientId) {
        socket.to(`user-${recipientId}`).emit('newMessage', msgData);
        socket.emit('newMessage', msgData); // Send back to sender
      } else {
        io.emit('newMessage', msgData); // Public message
      }
    } catch (err) {
      console.error('Database insert error:', err);
      socket.emit('error', { message: 'Failed to send message' });
    }
  });

  socket.on('react', async ({ messageId, reaction }) => {
    try {
      const reactionData = new Reaction({
        messageId,
        userId: socket.user.id,
        reaction,
        username: socket.user.username,
      });
      await reactionData.save();
      io.emit('newReaction', { messageId, reaction, username: socket.user.username });
    } catch (err) {
      console.error('Reaction insert error:', err);
      socket.emit('error', { message: 'Failed to add reaction' });
    }
  });

  socket.on('typing', ({ recipientId }) => {
    if (recipientId) {
      socket.to(`user-${recipientId}`).emit('typing', socket.user.username);
    } else {
      socket.broadcast.emit('typing', socket.user.username);
    }
  });

  socket.on('stopTyping', ({ recipientId }) => {
    if (recipientId) {
      socket.to(`user-${recipientId}`).emit('stopTyping', socket.user.username);
    } else {
      socket.broadcast.emit('stopTyping', socket.user.username);
    }
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
    onlineUsers = onlineUsers.filter((u) => u.id !== socket.user.id);
    io.emit('onlineUsers', onlineUsers);
  });
});

// Start the server
const PORT = process.env.PORT || 5500;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});