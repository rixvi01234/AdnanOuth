const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const User = require('../models/User');

// Register
router.post('/register', async (req, res) => {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = new User({ ...req.body, password: hashedPassword });
    await user.save();
    res.redirect('/');
});

// Login
router.post('/login', async (req, res) => {
    const user = await User.findOne({ email: req.body.email });
    const match = user && await bcrypt.compare(req.body.password, user.password);
    if (match) {
        req.session.userId = user._id;
        res.redirect('/dashboard');
    } else {
        res.send('Invalid credentials');
    }
});

module.exports = router;
