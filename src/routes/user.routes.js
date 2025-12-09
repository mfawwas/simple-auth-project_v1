const express = require('express');
const { signup, login, forgotPassword, resetPassword } = require('../controller/user.controller');
const router = express.Router();


router.post('/signup', signup);
router.post('/login', login);
router.put('/forgot-password', forgotPassword);    
router.put('/reset-password', resetPassword);


module.exports = router;