const User = require('../models/user.models');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// User Signup Controller
const signup = async (req, res) => {
    const { name, username, email, password } = req.body;
    try {
        if (!name || !username || !email || !password) {
            return res.status(400).json({ message: 'All input fields are required' });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(409).json({ message: 'User with this email already exists' });
        }

        // Hash user password
        const hashedPassword = await bcrypt.hash(password, 10);

        // OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpiry = new Date(Date.now() + 10 * 60 * 1000);

        // Create new user
        const newUser = new User({
            name,
            username,
            email,
            password: hashedPassword,
            otp,
            otpExpiry
        });

        await newUser.save();
        return res.status(201).json({ message: 'User registration successfull, please verify your email', otp  });
    } catch (err) {
        console.error('Error during user signup:', err);
        return res.status(500).json({ message: 'Internal server error' });
    }
};

// User login controller
const login = async (req, res) => {
    const { email, password } = req.body;
    try {
        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ message: 'User not found' });
        }

        if (!user.isVerified) {
            return res.status(401).json({ message: 'Please verify your account to continue' });
        }

        const comparePassword = await bcrypt.compare(password, user.password);
        if (!comparePassword) {
            return res.status(401).json({ message: 'Invalid password' });
        }

        const token = jwt.sign({ userId: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
        return res.status(200).json({ message: 'Login successful' });
    } catch (err) {
        console.error('Error during user login:', err);
        return res.status(500).json({ message: 'Internal server error' });
    }
};

// Forgot Password controller
const forgotPassword = async (req, res) => {
    const { email } = req.body;
    try {
        if (!email) {
            return res.status(400).json({ message: 'Email is required' });
        }

        const user = await User.findOne ({ email });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        user.otp = otp;
        await user.save();
        return res.status(200).json({ message: 'OTP sent to your email' , otp});
    } catch (err) {
        console.error('Process error:', err);
        return res.status(500).json({ message: 'Internal server error' });
    }
};

const resetPassword = async (req, res) => {
    const { otp, newPassword } = req.body;
    try {
        if (!otp || !newPassword) {
            return res.status(400).json({ message: 'All input fields are required' });
        }
        const user = await User.findOne({ otp });
        if (!user) {
            return res.status(404).json({ message: 'Invalid OTP' });
        }
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        user.otp = null; 
        await user.save();
        return res.status(200).json({ message: 'Password reset successful' });
    } catch (err) {
        console.error('Error during password reset:', err);
        return res.status(500).json({ message: 'Internal server error' });
    }
};

const getAllUsers = async (req, res) => {
    const {role} = req.user;
    if (role !== 'admin') {
        return res.status(403).json({ message: 'Access denied.' });
    }
    try {
        const users = await User.find().select('-password -otp -otpExpiry');
        return res.status(200).json(users);
    } catch (err) {
        console.error('Error fetching users:', err);
        return res.status(500).json({ message: 'Internal server error' });
    }
};

const verifyOtp = async (req, res) => {
    const {otp} = req.body;
    try {
        if (!otp) {
            return res.status(400).json({ message: 'OTP is required' });
        }

        const user = await User.findOne({otp});
        if (!user) {
            return res.status(404).json({ message: 'Invalid OTP' });
        }
        if (user.otpExpiry < new Date()) {
            return res.status(400).json({ message: 'OTP has expired' });
        }

        user.isVerified = true;
        user.otp = null;
        user.otpExpiry = null;
        await user.save();
        return res.status(200).json({ message: 'Account verified successfully' });
    } catch (err) {
        console.error('Error during OTP verification:', err);
        return res.status(500).json({ message: 'Internal server error' });
    }
};

// Exporting Functions
module.exports = {
    signup,
    login,
    forgotPassword,
    resetPassword,
    getAllUsers,
    verifyOtp
};