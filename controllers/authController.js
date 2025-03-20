const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fetch = require('node-fetch');
const { findUserByEmail, findUserByUsername, findUserById, createUser } = require('../db/database');

// Get register page
const getRegisterPage = (req, res) => {
  res.render('register', { error: req.query.error, success: req.query.success });
};

// Register new user
const register = async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Validate input
    if (!username || !email || !password) {
      return res.render('register', { error: 'All fields are required' });
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.render('register', { error: 'Invalid email format' });
    }

    // Check password length
    if (password.length < 8) {
      return res.render('register', { error: 'Password must be at least 8 characters long' });
    }

    // Check if username already exists
    const existingUsername = await findUserByUsername(username);
    if (existingUsername) {
      return res.render('register', { error: 'Username is already taken' });
    }

    // Check if email already exists
    const existingEmail = await findUserByEmail(email);
    if (existingEmail) {
      return res.render('register', { error: 'Email is already registered' });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create new user
    await createUser(username, email, hashedPassword);

    // Redirect to login with success message
    res.redirect('/login?success=Registration successful! Please log in');
  } catch (error) {
    console.error('Registration error:', error);
    res.render('register', { error: 'An error occurred during registration' });
  }
};

// Get login page
const getLoginPage = (req, res) => {
  res.render('login', { 
    error: req.query.error, 
    success: req.query.success,
    recaptchaSiteKey: process.env.RECAPTCHA_SITE_KEY 
  });
};

// Login user
const login = async (req, res) => {
  try {
    const { userIdentifier, password, 'g-recaptcha-response': recaptchaToken } = req.body;

    // Validate input
    if (!userIdentifier || !password) {
      return res.render('login', { 
        error: 'Username/email and password are required',
        recaptchaSiteKey: process.env.RECAPTCHA_SITE_KEY 
      });
    }

    // Verify reCAPTCHA
    const recaptchaResponse = await fetch('https://www.google.com/recaptcha/api/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `secret=${process.env.RECAPTCHA_SECRET_KEY}&response=${recaptchaToken}`
    });

    const recaptchaData = await recaptchaResponse.json();

    if (!recaptchaData.success) {
      return res.render('login', { 
        error: 'Invalid reCAPTCHA. Please try again',
        recaptchaSiteKey: process.env.RECAPTCHA_SITE_KEY 
      });
    }

    // Check if user exists (by email or username)
    const isEmail = userIdentifier.includes('@');
    const user = isEmail 
      ? await findUserByEmail(userIdentifier)
      : await findUserByUsername(userIdentifier);

    if (!user) {
      return res.render('login', { 
        error: 'Invalid credentials',
        recaptchaSiteKey: process.env.RECAPTCHA_SITE_KEY 
      });
    }

    // Validate password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.render('login', { 
        error: 'Invalid credentials',
        recaptchaSiteKey: process.env.RECAPTCHA_SITE_KEY 
      });
    }

    // Generate JWT token (valid for 15 minutes)
    const token = jwt.sign(
      { id: user.id, username: user.username, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRY }
    );

    // Set token in cookie
    res.cookie('token', token, {
      httpOnly: true,
      maxAge: 15 * 60 * 1000, // 15 minutes
      sameSite: 'strict'
    });

    // Redirect to profile page
    res.redirect('/profile');
  } catch (error) {
    console.error('Login error:', error);
    res.render('login', { 
      error: 'An error occurred during login',
      recaptchaSiteKey: process.env.RECAPTCHA_SITE_KEY 
    });
  }
};

// Get user profile
const getProfile = async (req, res) => {
  try {
    const user = await findUserById(req.user.id);
    if (!user) {
      return res.redirect('/login?error=User not found');
    }

    res.render('profile', { user });
  } catch (error) {
    console.error('Profile error:', error);
    res.redirect('/login?error=Error retrieving profile');
  }
};

// Logout user
const logout = (req, res) => {
  res.clearCookie('token');
  res.redirect('/login?success=Successfully logged out');
};

module.exports = {
  getRegisterPage,
  register,
  getLoginPage,
  login,
  getProfile,
  logout
};