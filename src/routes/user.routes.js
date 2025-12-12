const express = require('express');
const { signup, login, forgotPassword, resetPassword, getAllUsers, verifyOtp } = require('../controller/user.controller');
const auth = require('../config/auth');
const router = express.Router();


router.post('/signup', signup);
router.post('/login', login);
router.put('/forgot-password', forgotPassword);    
router.put('/reset-password', resetPassword);
router.get('/all-users', auth, getAllUsers);
router.put('/verify-otp', verifyOtp);


module.exports = router;