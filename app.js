require('dotenv').config();
const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const authController = require('./controllers/authController');
const authMiddleware = require('./middleware/authMiddleware');
const { initDb } = require('./db/database');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// View engine setup
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Initialize database
initDb();

// Routes
app.get('/', (req, res) => {
  res.redirect('/login');
});

// Authentication routes
app.get('/register', authController.getRegisterPage);
app.post('/register', authController.register);
app.get('/login', authController.getLoginPage);
app.post('/login', authController.login);
app.get('/profile', authMiddleware.verifyToken, authController.getProfile);
app.get('/logout', authController.logout);

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});