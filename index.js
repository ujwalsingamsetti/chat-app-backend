const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: [
      'http://localhost:3000',
      'https://venerable-donut-3b4f8a.netlify.app',
      'https://chat.ujwal.info',
    ],
    methods: ['GET', 'POST', 'DELETE'],
    credentials: true,
  },
});

app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: [
    'http://localhost:3000',
    'https://venerable-donut-3b4f8a.netlify.app',
    'https://chat.ujwal.info',
  ],
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI || 'mongodb+srv://ujwal:ujwal@chat-app.0xknl.mongodb.net/?retryWrites=true&w=majority&appName=chat-app', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log('MongoDB connected successfully')).catch(err => console.error('MongoDB connection error:', err));

// Mongoose Schemas
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});
const User = mongoose.model('User', userSchema);

const messageSchema = new mongoose.Schema({
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  content: { type: String, required: true },
  recipient: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  room: { type: String, default: 'public' },
  messageId: { type: String },
  createdAt: { type: Date, default: Date.now },
});
const Message = mongoose.model('Message', messageSchema);

// Middleware
const authenticateToken = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ message: 'Authentication failed' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');
    req.userId = decoded.userId;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
};

const authenticateSocket = async (socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    if (!token) return next(new Error('Authentication error: No token provided'));

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret');
    socket.userId = decoded.userId;
    const user = await User.findById(socket.userId).select('username');
    socket.user = user;
    next();
  } catch (error) {
    next(new Error('Authentication error'));
  }
};

// Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword });
    await user.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    res.status(400).json({ message: 'Error registering user', error: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user._id, username: user.username }, process.env.JWT_SECRET || 'your_jwt_secret', { expiresIn: '1h' });
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    });
    res.json({ token });
  } catch (error) {
    res.status(500).json({ message: 'Error logging in', error: error.message });
  }
});

app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
  });
  res.json({ message: 'Logged out successfully' });
});

app.get('/messages/:room?', authenticateToken, async (req, res) => {
  try {
    const room = req.params.room || 'public';
    const userId = req.userId;
    let messages = await Message.find({
      $or: [
        { room, recipient: null },
        { recipient: userId },
        { sender: userId, recipient: { $ne: null } },
      ],
    })
      .populate('sender', 'username')
      .populate('recipient', 'username')
      .sort({ createdAt: 1 });

    messages = messages.filter(msg => msg.sender?.username && (!msg.recipient || msg.recipient?.username));
    res.json(messages);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.delete('/messages/public', authenticateToken, async (req, res) => {
  try {
    await Message.deleteMany({ room: 'public', recipient: null });
    io.to('public').emit('chat-cleared');
    res.json({ message: 'Public chat cleared' });
  } catch (error) {
    res.status(500).json({ message: 'Error clearing public chat' });
  }
});

// Socket.IO Logic
const onlineUsers = new Map();
io.use(authenticateSocket);

io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  onlineUsers.set(socket.id, { userId: socket.userId, username: socket.user?.username });
  io.emit('online-users', Array.from(onlineUsers.values()));

  socket.on('join-room', (room) => {
    socket.join(room || 'public');
  });

  socket.on('message', async (msg) => {
    try {
      if (!socket.userId || !msg.content) return;

      if (msg.id) {
        const existingMessage = await Message.findOne({ messageId: msg.id });
        if (existingMessage) return;
      }

      const messageData = new Message({
        sender: socket.userId,
        content: msg.content,
        recipient: msg.recipient || null,
        room: msg.recipient ? null : msg.room || 'public',
        messageId: msg.id,
      });
      await messageData.save();

      const populatedMessage = await Message.findById(messageData._id)
        .populate('sender', 'username')
        .populate('recipient', 'username');
      const messageToEmit = { ...populatedMessage.toObject(), id: msg.id };

      if (msg.recipient) {
        const recipientSocketId = Array.from(onlineUsers.entries())
          .find(([_, user]) => user.userId.toString() === msg.recipient.toString())?.[0];
        if (recipientSocketId) {
          io.to(recipientSocketId).emit('message', messageToEmit);
        }
        io.to(socket.id).emit('message', messageToEmit);
      } else {
        io.to(messageData.room).emit('message', messageToEmit);
      }
    } catch (err) {
      console.error('Socket message error:', err.message);
    }
  });

  socket.on('typing', ({ recipientId }) => {
    const user = onlineUsers.get(socket.id);
    if (user) {
      if (recipientId) {
        const recipientSocketId = Array.from(onlineUsers.entries())
          .find(([_, u]) => u.userId === recipientId)?.[0];
        if (recipientSocketId) {
          io.to(recipientSocketId).emit('typing', user.username);
        }
      } else {
        io.to('public').emit('typing', user.username);
      }
    }
  });

  socket.on('stopTyping', ({ recipientId }) => {
    if (recipientId) {
      const recipientSocketId = Array.from(onlineUsers.entries())
        .find(([_, u]) => u.userId === recipientId)?.[0];
      if (recipientSocketId) {
        io.to(recipientSocketId).emit('stopTyping');
      }
    } else {
      io.to('public').emit('stopTyping');
    }
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
    onlineUsers.delete(socket.id);
    io.emit('online-users', Array.from(onlineUsers.values()));
  });
});

const PORT = process.env.PORT || 5500;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));