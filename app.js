const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const userRoutes = require('./routes/users');
const User = require('./models/User');
require('dotenv').config();


const app = express();

// Google OAuth credentials
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const Mongo=process.env.Mongo

mongoose.connect(Mongo)
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('Could not connect to MongoDB:', err));

app.use(session({ 
    secret: 'secret', 
    resave: false, 
    saveUninitialized: false 
}));

// Passport
app.use(passport.initialize());
app.use(passport.session());

app.use(bodyParser.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.use('/api/users', userRoutes);

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) {
        done(err, null);
    }
});

// Google 
passport.use(new GoogleStrategy({
    clientID:process.env.GOOGLE_CLIENT_ID,
    clientSecret:process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/callback"
},
async function(accessToken, refreshToken, profile, done) {
    try {
        // Check if user already exists
        let user = await User.findOne({ googleId: profile.id });
        
        if (!user) {
            // Create new user if doesn't exist
            user = await User.create({
                googleId: profile.id,
                name: profile.displayName,
                email: profile.emails[0].value,
                picture: profile.photos[0].value
            });
        }
        
        return done(null, user);
    } catch (err) {
        return done(err, null);
    }
}));

// Middleware
function isAuthenticated(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.redirect('/login');
}

// Routes
app.get('/', (req, res) => {
    res.render('form');
});

app.get('/login', (req, res) => {
    if (req.isAuthenticated()) {
        return res.redirect('/dashboard');
    }
    res.render('login');
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find user by email
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).send('Invalid email or password');
        }

        // Compare password
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(400).send('Invalid email or password');
        }

        // Set session with user's MongoDB ObjectId
        req.session.userId = user._id;
        res.redirect('/dashboard');
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).send('An error occurred during login');
    }
});

app.get('/dashboard', isAuthenticated, async (req, res) => {
    try {
        res.send(`
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <title>Dashboard</title>
                <style>
                    body {
                        margin: 0;
                        height: 100vh;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        font-family: Arial, sans-serif;
                        background: linear-gradient(to right, #00c6ff, #0072ff);
                        color: #fff;
                    }

                    .dashboard {
                        background: rgba(255, 255, 255, 0.15);
                        padding: 40px;
                        border-radius: 15px;
                        text-align: center;
                        box-shadow: 0 8px 16px rgba(0, 0, 0, 0.3);
                        max-width: 500px;
                        width: 100%;
                    }

                    img {
                        margin-top: 20px;
                        width: 120px;
                        height: 120px;
                        border-radius: 50%;
                        object-fit: cover;
                    }

                    button {
                        margin-top: 30px;
                        padding: 10px 20px;
                        background-color: #ff4444;
                        color: white;
                        border: none;
                        border-radius: 5px;
                        cursor: pointer;
                        font-size: 16px;
                        transition: background-color 0.3s ease;
                    }

                    button:hover {
                        background-color: #cc0000;
                    }

                    h1 {
                        margin-bottom: 10px;
                    }

                    p {
                        font-size: 16px;
                    }
                </style>
            </head>
            <body>
                <div class="dashboard">
                    <h1>Welcome to your dashboard, ${req.user.name}</h1>
                    <p>Your email: ${req.user.email}</p>
                    ${req.user.picture ? `<img src="${req.user.picture}" alt="Profile Picture">` : ''}
                    <form action="/logout" method="POST">
                        <button type="submit">Logout</button>
                    </form>
                </div>
            </body>
            </html>
        `);
    } catch (error) {
        console.error('Error in dashboard:', error);
        res.status(500).send('An error occurred');
    }
});


app.post('/submit', async (req, res) => {
    try {
        const { name, email, password } = req.body;

        // Basic validation
        if (!name || !email || !password) {
            return res.status(400).send('All fields are required.');
        }

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).send('User with this email already exists.');
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create new user
        const user = new User({
            name,
            email,
            password: hashedPassword
        });

        // Save user to database
        await user.save();

        // Set session
        req.session.userId = user._id;

        // Redirect to dashboard
        res.redirect('/dashboard');
    } catch (error) {
        console.error('Error during user registration:', error);
        res.status(500).send('An error occurred during registration.');
    }
});

// Google Auth Routes
app.get('/auth/google',
    passport.authenticate('google', { 
        scope: ['profile', 'email']
    })
);

app.get('/auth/google/callback',
    passport.authenticate('google', { 
        failureRedirect: '/login',
        successRedirect: '/dashboard'
    })
);

// Update logout route to use passport's logout
app.post('/logout', function(req, res, next) {
    req.logout(function(err) {
        if (err) { return next(err); }
        res.redirect('/');
    });
});

// Server added
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
