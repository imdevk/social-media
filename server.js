const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const path = require('path');
const crypto = require('crypto');
const User = require('./models/User');
const Post = require('./models/Post');
dotenv.config();

const app = express();
app.use(express.json());
app.use(express.static('public'));

mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
    .then(() => console.log('Connected to MongoDB'))
    .catch((err) => console.error('MongoDB connection error:', err));

const authenticateJWT = (req, res, next) => {
    const token = req.headers.authorization && req.headers.authorization.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'Access denied' });
    }
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(400).json({ error: 'Invalid token' });
    }
};

app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const user = new User({ username, email, password });
        await user.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.post('/api/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        const resetToken = crypto.randomBytes(3).toString('hex');
        user.resetToken = resetToken;
        user.resetTokenExpiration = Date.now() + 3600000; // 1 h
        await user.save();

        console.log(`Reset token for ${email}: ${resetToken}`);

        res.json({ message: 'Password reset token generated.', resetToken });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.post('/api/reset-password', async (req, res) => {
    try {
        const { token, newPassword } = req.body;
        const user = await User.findOne({
            resetToken: token,
            resetTokenExpiration: { $gt: Date.now() },
        });
        if (!user) {
            return res.status(400).json({ error: 'Invalid or expired reset token' });
        }
        user.password = newPassword;
        user.resetToken = undefined;
        user.resetTokenExpiration = undefined;
        await user.save();
        res.json({ message: 'Password reset successful' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.post('/api/posts', authenticateJWT, async (req, res) => {
    try {
        const { content } = req.body;
        const post = new Post({ content, author: req.user.userId });
        await post.save();
        res.status(201).json({ message: 'Post created successfully' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.get('/api/posts', async (req, res) => {
    try {
        const posts = await Post.find().populate('author', 'username').populate('comments.user', 'username');
        res.json(posts);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.get('/api/posts/:postId', async (req, res) => {
    try {
        const { postId } = req.params;
        const post = await Post.findById(postId).populate('author', 'username').populate('comments.user', 'username');
        if (!post) {
            return res.status(404).json({ error: 'Post not found' });
        }
        res.json(post);
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});


app.put('/api/posts/:postId', authenticateJWT, async (req, res) => {
    try {
        const { postId } = req.params;
        const { content } = req.body;
        const post = await Post.findById(postId);
        if (!post) {
            return res.status(404).json({ error: 'Post not found' });
        }
        if (post.author.toString() !== req.user.userId) {
            return res.status(403).json({ error: 'Unauthorized' });
        }
        post.content = content;
        await post.save();
        res.json({ message: 'Post updated successfully' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.post('/api/posts/:postId/like', authenticateJWT, async (req, res) => {
    try {
        const { postId } = req.params;
        const post = await Post.findById(postId);
        if (!post) {
            return res.status(404).json({ error: 'Post not found' });
        }
        if (post.likes.includes(req.user.userId)) {
            post.likes.pull(req.user.userId);
        } else {
            post.likes.push(req.user.userId);
        }
        await post.save();
        res.json({ message: 'Post liked/unliked successfully' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.post('/api/posts/:postId/comment', authenticateJWT, async (req, res) => {
    try {
        const { postId } = req.params;
        const { text } = req.body;
        const post = await Post.findById(postId);
        if (!post) {
            return res.status(404).json({ error: 'Post not found' });
        }
        post.comments.push({ user: req.user.userId, text });
        await post.save();
        res.json({ message: 'Comment added successfully' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.delete('/api/posts/:postId', authenticateJWT, async (req, res) => {
    try {
        const { postId } = req.params;
        const post = await Post.findById(postId);
        if (!post) {
            return res.status(404).json({ error: 'Post not found' });
        }
        if (post.author.toString() !== req.user.userId) {
            return res.status(403).json({ error: 'Unauthorized' });
        }
        await Post.deleteOne({ _id: postId });
        res.json({ message: 'Post deleted successfully' });
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
