# Full-Stack Authentication System with Google reCAPTCHA

A complete authentication system built with Node.js, Express, PostgreSQL, and Google reCAPTCHA integration.

## Features

- User registration with input validation
- Secure login with Google reCAPTCHA protection
- JWT-based authentication with 15-minute session duration
- Protected profile route
- Password hashing with bcrypt
- Session expiry warning
- PostgreSQL database with raw SQL queries

## Prerequisites

- Node.js (v14 or higher)
- PostgreSQL database (or Neon PostgreSQL account)
- Google reCAPTCHA keys (site key and secret key)

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/auth-system.git
   cd auth-system
   ```

2. Install dependencies:
   ```
   npm install
   ```

3. Set up your environment variables by creating a `.env` file in the root directory with the following content:
   ```
   # Server Configuration
   PORT=3000

   # Choose one of the two database configuration options:
   
   # Option 1: For local PostgreSQL
   # DB_HOST=localhost
   # DB_USER=postgres
   # DB_PASSWORD=your_postgres_password
   # DB_NAME=auth_system
   # DB_PORT=5432
   
   # Option 2: For Neon PostgreSQL
   DATABASE_URL=your_neon_postgresql_connection_string_here

   # JWT Configuration
   JWT_SECRET=your_jwt_secret_key_here
   JWT_EXPIRY=15m

   # Google reCAPTCHA
   RECAPTCHA_SITE_KEY=your_recaptcha_site_key_here
   RECAPTCHA_SECRET_KEY=your_recaptcha_secret_key_here
   ```

4. Replace the placeholder values with your actual credentials and keys.

## Database Setup

### Option 1: Local PostgreSQL

If using a local PostgreSQL installation:

1. Create a PostgreSQL database:
   ```
   createdb auth_system
   ```

### Option 2: Neon PostgreSQL

If using Neon PostgreSQL (serverless PostgreSQL):

1. Go to [Neon](https://neon.tech/) and sign up for an account
2. Create a new project
3. Once your project is created, go to the "Connection Details" tab
4. Copy the connection string that looks like: `postgresql://username:password@host:port/database`
5. Add this connection string to your `.env` file as `DATABASE_URL`

## Getting reCAPTCHA Keys

1. Go to the [Google reCAPTCHA Admin Console](https://www.google.com/recaptcha/admin)
2. Sign in with your Google account
3. Register a new site
4. Choose reCAPTCHA v2 "I'm not a robot" Checkbox
5. Add your domains (use `localhost` for local development)
6. Accept the terms of service and click "Submit"
7. Copy the "Site key" and "Secret key" to your `.env` file

## Running the Application

1. Start the development server:
   ```
   npm run dev
   ```

2. Access the application in your browser:
   ```
   http://localhost:3000
   ```

## Project Structure

```
auth-system/
├── .env                    # Environment variables
├── package.json            # Project dependencies
├── app.js                  # Main application file
├── controllers/
│   └── authController.js   # User authentication logic
├── middleware/
│   └── authMiddleware.js   # JWT authentication middleware
├── db/
│   └── database.js         # Database connection and queries
├── utils/
│   └── helpers.js          # Utility functions
└── views/
    ├── register.ejs        # Registration page
    ├── login.ejs           # Login page with reCAPTCHA
    ├── profile.ejs         # User profile page
    └── partials/
        ├── header.ejs      # Header partial
        └── footer.ejs      # Footer partial
```

## Security Features

- Password hashing with bcrypt
- JWT authentication with short expiry time
- HTTP-only cookies for token storage
- Google reCAPTCHA for bot protection
- Input validation on both client and server sides
- Session expiry warning

## Optional Enhancements

You may consider adding these optional features:

1. **Rate Limiting**: Add the `express-rate-limit` package to limit login attempts:

```javascript
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 login attempts per windowMs
  message: 'Too many login attempts, please try again after 15 minutes'
});

app.post('/login', loginLimiter, authController.login);
```

2. **Email Verification**: Add email verification using Nodemailer.

3. **Password Reset**: Implement a password reset functionality.

4. **Two-Factor Authentication**: Add 2FA using libraries like Speakeasy.

## License
MIT
#   F u l l - S t a c k - A u t h e n t i c a t i o n - S y s t e m - w i t h - G o o g l e - r e C A P T C H A - a n d - j w t  
 