// server/routes/auth.js
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const User = require('../models/User');
const { validate, registerSchema, loginSchema } = require('../utils/validate');
const env = require('../config/env');

const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: 'Too many login attempts, please try again later.',
});

router.post('/register', validate(registerSchema), async (req, res, next) => {
  try {
    const { username, password } = req.body;
    console.log('Register attempt for username:', username);

    const existingUser = await User.findOne({ username });
    if (existingUser) {
      const error = new Error('Username already exists');
      error.status = 400;
      throw error;
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword });
    await user.save();
    console.log('User registered successfully:', username);

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    next(error);
  }
});

router.post('/login', loginLimiter, validate(loginSchema), async (req, res, next) => {
  try {
    const { username, password } = req.body;
    console.log('Login attempt for username:', username);

    const user = await User.findOne({ username });
    if (!user) {
      const error = new Error('Invalid username or password');
      error.status = 401;
      throw error;
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      const error = new Error('Invalid username or password');
      error.status = 401;
      throw error;
    }

    const token = jwt.sign({ userId: user._id }, env.JWT_SECRET, { expiresIn: '1h' });
    console.log('Login successful for username:', username);

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 3600000,
      path: '/',
    });

    res.status(200).json({ message: 'Login successful', token }); // Add token to response body
  } catch (error) {
    next(error);
  }
});

module.exports = router;