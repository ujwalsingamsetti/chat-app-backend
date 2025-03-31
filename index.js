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
app.use((req, res, next) => {
  console.log(`Received request: ${req.method} ${req.url}`);
  next();
});
app.use(express.json());

app.use(cors({
  origin: (origin, callback) => {
    const allowedOrigins = [
      'http://localhost:3000', // For local development
      'https://venerable-donut-3b4f8a.netlify.app', // Your Netlify domain
      'https://chat.ujwal.info', // Your custom domain
    ];
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'], // Explicitly allow these methods
  allowedHeaders: ['Content-Type', 'Authorization'], // Allow these headers
}));

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
    origin: (origin, callback) => {
      const allowedOrigins = [
        'http://localhost:3000', // For local development
        'https://venerable-donut-3b4f8a.netlify.app', // Your Netlify domain
        'https://chat.ujwal.info', // Your custom domain
      ];
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },
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


// Register endpoint with strong password validation
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password required' });
  }

  // ✅ Validate password before checking username
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  if (!passwordRegex.test(password)) {
    console.log("Weak password detected:", password);
    return res.status(400).json({
      message: 'Password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character.',
    });
  }

  try {
    // Check if username already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: 'Username already exists' });
    }

    // Hash password and save user
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword });

    await user.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ message: 'Registration failed due to server error' });
  }
});



// Login endpoint
app.post('/login', async (req, res) => {
  console.log('Received request: POST /login');
  try {
    const { username, password } = req.body;
    console.log('Login attempt for username:', username);

    // Find the user in MongoDB
    const user = await User.findOne({ username });
    if (!user) {
      console.log('User not found:', username);
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    // Compare the password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      console.log('Invalid password for username:', username);
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    // Generate a JWT token
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    console.log('Login successful for username:', username, 'Token generated:', token);

    res.status(200).json({ token });
  } catch (error) {
    console.error('Error during login:', error);
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

// Catch-all route (place at the end)
app.use((req, res) => {
  console.log('Catch-all route triggered for:', req.method, req.url);
  res.status(404).send('Not Found');
});

// Start the server
const PORT = process.env.PORT || 5500;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});