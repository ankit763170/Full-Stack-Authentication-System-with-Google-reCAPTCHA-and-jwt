const jwt = require('jsonwebtoken');

const verifyToken = (req, res, next) => {
  // Get token from cookie or authorization header
  const token = req.cookies.token || (req.headers.authorization && req.headers.authorization.split(' ')[1]);
  
  if (!token) {
    return res.redirect('/login?error=Please log in to access this page');
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.redirect('/login?error=Session expired. Please log in again');
    }
    return res.redirect('/login?error=Invalid session. Please log in again');
  }
};

module.exports = {
  verifyToken
};