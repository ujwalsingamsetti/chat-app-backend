const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { Server } = require('socket.io');
const http = require('http');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: (origin, callback) => {
      const allowedOrigins = [
        'http://localhost:3000',
        'https://venerable-donut-3b4f8a.netlify.app',
        'https://chat.ujwal.info',
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

app.use(express.json());
app.use(cors({
  origin: (origin, callback) => {
    const allowedOrigins = [
      'http://localhost:3000',
      'https://venerable-donut-3b4f8a.netlify.app',
      'https://chat.ujwal.info',
    ];
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/chat-app', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});
const User = mongoose.model('User', UserSchema);

const MessageSchema = new mongoose.Schema({
  username: String,
  message: String,
  timestamp: { type: Date, default: Date.now },
  recipientId: { type: String, default: null },
  reactions: [{ username: String, reaction: String }],
});
const Message = mongoose.model('Message', MessageSchema);

const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
};

app.post('/register', async (req, res) => {
  console.log('Received request: POST /register');
  try {
    const { username, password } = req.body;
    console.log('Register attempt for username:', username);

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword });
    await user.save();
    console.log('User registered successfully:', username);

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Error during registration:', error);
    res.status(400).json({ message: 'Username already exists' });
  }
});

app.post('/login', async (req, res) => {
  console.log('Received request: POST /login');
  try {
    const { username, password } = req.body;
    console.log('Login attempt for username:', username);

    const user = await User.findOne({ username });
    if (!user) {
      console.log('User not found:', username);
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      console.log('Invalid password for username:', username);
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    console.log('Login successful for username:', username, 'Token generated:', token);

    res.status(200).json({ token });
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/messages', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    const recipientId = req.query.recipientId || null;
    const messages = await Message.find({
      $or: [
        { recipientId: null }, // Public messages
        { recipientId: user._id.toString() }, // Messages sent to the user
        { recipientId: recipientId }, // Messages sent to the recipient
      ],
    }).sort({ timestamp: 1 });
    res.json(messages);
  } catch (error) {
    console.error('Error fetching messages:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/clear-public-chat', authenticateToken, async (req, res) => {
  try {
    // Delete all messages where recipientId is null (public chat messages)
    await Message.deleteMany({ recipientId: null });
    console.log('Public chat messages cleared by user:', req.user.userId);

    // Emit a Socket.IO event to notify all connected clients
    io.emit('publicChatCleared');
    console.log('Emitted publicChatCleared event to all clients');

    res.status(200).json({ message: 'Public chat cleared successfully' });
  } catch (error) {
    console.error('Error clearing public chat:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
    io.emit('onlineUsers', Array.from(io.sockets.sockets).map(([id, s]) => ({
      id,
      username: s.username,
    })));
  });

  socket.on('sendMessage', async (data) => {
    const token = socket.handshake.auth.token;
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await User.findById(decoded.userId);
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
        const token = socket.handshake.auth.token;
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.userId);
        message.reactions.push({ username: user.username, reaction: data.reaction });
        await message.save();
        io.emit('newReaction', { messageId: data.messageId, username: user.username, reaction: data.reaction });
      }
    } catch (error) {
      console.error('Error adding reaction:', error);
    }
  });

  socket.on('typing', async(data) => {
    const token = socket.handshake.auth.token;
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await User.findById(decoded.userId);
      socket.broadcast.emit('typing', user.username);
    } catch (error) {
      console.error('Error handling typing event:', error);
    }
  });

  socket.on('stopTyping', () => {
    socket.broadcast.emit('stopTyping');
  });

  const token = socket.handshake.auth.token;
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = User.findById(decoded.userId);
    socket.username = user.username;
    io.emit('onlineUsers', Array.from(io.sockets.sockets).map(([id, s]) => ({
      id,
      username: s.username,
    })));
  } catch (error) {
    console.error('Socket authentication error:', error);
    socket.emit('connect_error', { message: 'Authentication error: Invalid token' });
    socket.disconnect();
  }
});

const PORT = process.env.PORT || 5500;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));