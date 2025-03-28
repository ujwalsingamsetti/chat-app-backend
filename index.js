const express = require('express');
const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const cors = require('cors');
require('dotenv').config();

// Initialize Express app
const app = express();
app.use(express.json());
app.use(cors({ origin: 'http://localhost:3000' }));

// Initialize SQLite database
const db = new sqlite3.Database('./chat.db', (err) => {
  if (err) {
    console.error('Database connection error:', err);
  } else {
    console.log('Connected to SQLite database');
    // Create users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT
    )`);
    // Create messages table
    db.run(`CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      userId TEXT,
      recipientId TEXT,
      message TEXT,
      timestamp TEXT
    )`);
    // Create reactions table
    db.run(`CREATE TABLE IF NOT EXISTS reactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      messageId INTEGER,
      userId TEXT,
      reaction TEXT
    )`);
  }
});

// Initialize Socket.IO server
const server = app.listen(5500, () => {
  console.log('Server running on port 5500');
});
const io = new Server(server, {
  cors: {
    origin: 'http://localhost:3000',
    methods: ['GET', 'POST']
  }
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

// REST API Endpoints
// Register endpoint
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password required' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  db.run(
    'INSERT INTO users (username, password) VALUES (?, ?)',
    [username, hashedPassword],
    (err) => {
      if (err) {
        console.error('Register error:', err);
        return res.status(400).json({ message: 'Username already exists' });
      }
      res.status(201).json({ message: 'User registered successfully' });
    }
  );
});

// Login endpoint
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password required' });
  }

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err) {
      console.error('Login error:', err);
      return res.status(500).json({ message: 'Server error' });
    }
    if (!user) {
      return res.status(400).json({ message: 'Invalid username or password' });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(400).json({ message: 'Invalid username or password' });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      process.env.JWT_SECRET || 'your_secret_key_here',
      { expiresIn: '1h' }
    );
    res.json({ token });
  });
});

// Fetch messages endpoint
app.get('/messages', authenticateToken, (req, res) => {
  const { recipientId } = req.query;
  const userId = req.user.id;

  let query = 'SELECT m.*, u.username FROM messages m JOIN users u ON m.userId = u.id WHERE recipientId IS NULL';
  let params = [];

  if (recipientId) {
    query = `
      SELECT m.*, u.username 
      FROM messages m 
      JOIN users u ON m.userId = u.id 
      WHERE (m.userId = ? AND m.recipientId = ?) OR (m.userId = ? AND m.recipientId = ?)
    `;
    params = [userId, recipientId, recipientId, userId];
  }

  db.all(query, params, (err, messages) => {
    if (err) {
      console.error('Fetch messages error:', err);
      return res.status(500).json({ message: 'Server error' });
    }

    // Fetch reactions for each message
    const messageIds = messages.map(m => m.id);
    if (messageIds.length === 0) {
      return res.json(messages);
    }

    db.all(
      'SELECT r.*, u.username FROM reactions r JOIN users u ON r.userId = u.id WHERE r.messageId IN (' + messageIds.map(() => '?').join(',') + ')',
      messageIds,
      (err, reactions) => {
        if (err) {
          console.error('Fetch reactions error:', err);
          return res.status(500).json({ message: 'Server error' });
        }

        const messagesWithReactions = messages.map(message => ({
          ...message,
          reactions: reactions.filter(r => r.messageId === message.id)
        }));
        res.json(messagesWithReactions);
      }
    );
  });
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
  if (!onlineUsers.some(u => u.id === socket.user.id)) {
    onlineUsers.push({ id: socket.user.id, username: socket.user.username });
    io.emit('onlineUsers', onlineUsers);
  }

  // Join user-specific room for private messaging
  socket.join(`user-${socket.user.id}`);

  socket.on('sendMessage', ({ message, recipientId }) => {
    console.log('Message received from', socket.user.username, 'to', recipientId ? `user ${recipientId}` : 'public', ':', message);
    const timestamp = new Date().toISOString();
    db.run(
      'INSERT INTO messages (userId, recipientId, message, timestamp) VALUES (?, ?, ?, ?)',
      [socket.user.id, recipientId || null, message, timestamp],
      function (err) {
        if (err) {
          console.error('Database insert error:', err);
          socket.emit('error', { message: 'Failed to send message' });
        } else {
          const msgData = {
            id: this.lastID,
            username: socket.user.username,
            message,
            recipientId,
            timestamp,
            reactions: []
          };
          console.log('Emitting newMessage:', msgData);
          if (recipientId) {
            socket.to(`user-${recipientId}`).emit('newMessage', msgData);
            socket.emit('newMessage', msgData); // Send back to sender
          } else {
            io.emit('newMessage', msgData); // Public message
          }
        }
      }
    );
  });

  socket.on('react', ({ messageId, reaction }) => {
    db.run(
      'INSERT INTO reactions (messageId, userId, reaction) VALUES (?, ?, ?)',
      [messageId, socket.user.id, reaction],
      (err) => {
        if (err) {
          console.error('Reaction insert error:', err);
          socket.emit('error', { message: 'Failed to add reaction' });
        } else {
          const reactionData = { messageId, reaction, username: socket.user.username };
          io.emit('newReaction', reactionData);
        }
      }
    );
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
    onlineUsers = onlineUsers.filter(u => u.id !== socket.user.id);
    io.emit('onlineUsers', onlineUsers);
  });
});