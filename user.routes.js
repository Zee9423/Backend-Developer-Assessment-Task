const express = require('express');
const router = express.Router();
const userController = require('../controllers/user.controller');
const authController = require('../controllers/auth.controller');

// Get all users (admin only)
router.get('/', authController.protect, authController.restrictTo('admin'), userController.getAllUsers);

// Get user by ID
router.get('/:id', authController.protect, userController.getUserById);

// Update user
router.put('/:id', authController.protect, userController.updateUser);

// Delete user
router.delete('/:id', authController.protect, userController.deleteUser);

module.exports = router;