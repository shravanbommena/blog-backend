const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

// Initialize environment variables
dotenv.config();

// Initialize Express app
const app = express();

// Middleware to parse JSON
app.use(express.json());
app.use(cors());

// Connect to MongoDB
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => {
    console.error("MongoDB connection failed:", err.message);
    process.exit(1);
  });

// Define User Schema
const UserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  role: {
    type: String,
    enum: ["admin", "author", "reader"],
    default: "reader",
  },
});

UserSchema.pre("save", async function (next) {
  if (!this.isModified("password")) {
    return next();
  }
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

const User = mongoose.model("User", UserSchema);

// Define Blog Post Schema
const BlogPostSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
  },
  content: {
    type: String,
    required: true,
  },
  author: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  created_at: {
    type: Date,
    default: Date.now,
  },
  updated_at: {
    type: Date,
    default: Date.now,
  },
  status: {
    type: String,
    enum: ["draft", "published"],
    default: "draft",
  },
});

const BlogPost = mongoose.model("BlogPost", BlogPostSchema);

// Define Comment Schema
const CommentSchema = new mongoose.Schema({
  post: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "BlogPost",
    required: true,
  },
  author: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  content: {
    type: String,
    required: true,
  },
  created_at: {
    type: Date,
    default: Date.now,
  },
  approved: {
    type: Boolean,
    default: false,
  },
});

const Comment = mongoose.model("Comment", CommentSchema);

// Middleware for authentication
const authMiddleware = async (req, res, next) => {
  const token = req.header("x-auth-token");
  if (!token) {
    return res.status(401).json({ error: "No token, authorization denied" });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded.user;
    next();
  } catch (err) {
    res.status(401).json({ error: "Token is not valid" });
  }
};

// Root route
app.get("/", (req, res) => {
  res.send("Root endpoint is working");
});

// Register route
app.post("/api/auth/register", async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const user = new User({ username, email, password });
    await user.save();
    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    res.status(500).json({ error: "User registration failed" });
  }
});

// Login route
app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ error: "Invalid credentials" });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: "Invalid credentials" });
    }
    const payload = {
      user: {
        id: user.id,
        role: user.role,
      },
    };
    jwt.sign(
      payload,
      process.env.JWT_SECRET,
      { expiresIn: "1h" },
      (err, token) => {
        if (err) throw err;
        res.json({ token });
      }
    );
  } catch (error) {
    res.status(500).json({ error: "Login failed" });
  }
});

// Blog Post routes

// Create a blog post
app.post("/api/blogposts", authMiddleware, async (req, res) => {
  const { title, content, status } = req.body;
  try {
    const newPost = new BlogPost({
      title,
      content,
      author: req.user.id,
      status,
    });
    await newPost.save();
    res.status(201).json(newPost);
  } catch (error) {
    res.status(500).json({ error: "Failed to create post" });
  }
});

// Read all blog posts with optional search and filtering
app.get("/api/blogposts", async (req, res) => {
  const { title, author, status } = req.query;
  try {
    const query = {};
    if (title) {
      query.title = new RegExp(title, "i"); // Case-insensitive search
    }
    if (author) {
      query.author = author;
    }
    if (status) {
      query.status = status;
    }
    const posts = await BlogPost.find(query).populate("author", "username");
    res.json(posts);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch posts" });
  }
});

// Read a single blog post
app.get("/api/blogposts/:id", async (req, res) => {
  try {
    const post = await BlogPost.findById(req.params.id).populate(
      "author",
      "username"
    );
    if (!post) {
      return res.status(404).json({ error: "Post not found" });
    }
    res.json(post);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch post" });
  }
});

// Update a blog post
app.put("/api/blogposts/:id", authMiddleware, async (req, res) => {
  const { title, content, status } = req.body;
  try {
    const post = await BlogPost.findById(req.params.id);
    if (!post) {
      return res.status(404).json({ error: "Post not found" });
    }
    if (post.author.toString() !== req.user.id) {
      return res.status(403).json({ error: "Not authorized" });
    }
    post.title = title;
    post.content = content;
    post.status = status;
    post.updated_at = Date.now();
    await post.save();
    res.json(post);
  } catch (error) {
    res.status(500).json({ error: "Failed to update post" });
  }
});

// Delete a blog post
app.delete("/api/blogposts/:id", authMiddleware, async (req, res) => {
  try {
    const post = await BlogPost.findById(req.params.id);
    if (!post) {
      return res.status(404).json({ error: "Post not found" });
    }
    if (post.author.toString() !== req.user.id) {
      return res.status(403).json({ error: "Not authorized" });
    }
    await post.remove();
    res.json({ message: "Post deleted" });
  } catch (error) {
    res.status(500).json({ error: "Failed to delete post" });
  }
});

// Comments routes

// Post a comment
app.post("/api/comments", authMiddleware, async (req, res) => {
  const { post, content } = req.body;
  try {
    const newComment = new Comment({
      post,
      author: req.user.id,
      content,
    });
    await newComment.save();
    res.status(201).json(newComment);
  } catch (error) {
    res.status(500).json({ error: "Failed to create comment" });
  }
});

// Approve a comment (admin only)
app.put("/api/comments/:id/approve", authMiddleware, async (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Not authorized" });
  }
  try {
    const comment = await Comment.findById(req.params.id);
    if (!comment) {
      return res.status(404).json({ error: "Comment not found" });
    }
    comment.approved = true;
    await comment.save();
    res.json(comment);
  } catch (error) {
    res.status(500).json({ error: "Failed to approve comment" });
  }
});

// Read comments for a blog post
app.get("/api/comments/post/:postId", async (req, res) => {
  try {
    const comments = await Comment.find({
      post: req.params.postId,
      approved: true,
    }).populate("author", "username");
    res.json(comments);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch comments" });
  }
});

// Read all blog posts with optional search, filtering, and pagination
// app.get('/api/blogposts', async (req, res) => {
//     const { title, author, status, page = 1, limit = 10 } = req.query;
//     try {
//         const query = {};
//         if (title) {
//             query.title = new RegExp(title, 'i'); // Case-insensitive search
//         }
//         if (author) {
//             query.author = author;
//         }
//         if (status) {
//             query.status = status;
//         }
//         const posts = await BlogPost.find(query)
//             .skip((page - 1) * limit)
//             .limit(parseInt(limit))
//             .populate('author', 'username');
//         res.json(posts);
//     } catch (error) {
//         res.status(500).json({ error: 'Failed to fetch posts' });
//     }
// });

// Fetch Top 5 Most Commented Posts
app.get("/api/blogposts/top-commented", async (req, res) => {
  try {
    const posts = await BlogPost.aggregate([
      {
        $lookup: {
          from: "comments",
          localField: "_id",
          foreignField: "post",
          as: "comments",
        },
      },
      {
        $addFields: {
          commentCount: { $size: "$comments" },
        },
      },
      {
        $sort: { commentCount: -1 },
      },
      {
        $limit: 5,
      },
    ]);
    res.json(posts);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch top commented posts" });
  }
});

// Fetch Number of Posts by Each Author
app.get("/api/blogposts/posts-by-author", async (req, res) => {
  try {
    const postsCountByAuthor = await BlogPost.aggregate([
      {
        $group: {
          _id: "$author",
          postCount: { $sum: 1 },
        },
      },
      {
        $lookup: {
          from: "users",
          localField: "_id",
          foreignField: "_id",
          as: "author",
        },
      },
      {
        $unwind: "$author",
      },
      {
        $project: {
          _id: 0,
          author: "$author.username",
          postCount: 1,
        },
      },
    ]);
    res.json(postsCountByAuthor);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch posts count by author" });
  }
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
