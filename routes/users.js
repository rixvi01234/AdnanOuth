const express = require('express');
const router = express.Router();
const User = require('../models/User');

// Auth middleware
function isAuthenticated(req, res, next) {
    if (req.session && req.session.userId) return next();
    return res.status(401).json({ message: 'Unauthorized' });
}

// 📥 Get all users (protected)
router.get('/', isAuthenticated, async (req, res) => {
    try {
        const users = await User.find({}, '-password'); // exclude password
        res.json(users);
    } catch (err) {
        res.status(500).json({ message: 'Server error' });
    }
});

// ➕ Create new user (testing/admin only – protected)
router.post('/', isAuthenticated, async (req, res) => {
    try {
        const user = new User(req.body);
        await user.save();
        res.status(201).json(user);
    } catch (err) {
        res.status(400).json({ message: 'Error creating user' });
    }
});

// 🔄 Update user
router.put('/:id', isAuthenticated, async (req, res) => {
    try {
        const updated = await User.findByIdAndUpdate(req.params.id, req.body, { new: true });
        res.json(updated);
    } catch (err) {
        res.status(400).json({ message: 'Error updating user' });
    }
});

// ❌ Delete user
router.delete('/:id', isAuthenticated, async (req, res) => {
    try {
        await User.findByIdAndDelete(req.params.id);
        res.json({ message: 'Deleted successfully' });
    } catch (err) {
        res.status(400).json({ message: 'Error deleting user' });
    }
});

module.exports = router;
