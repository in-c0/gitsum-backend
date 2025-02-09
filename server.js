// Load environment variables early
require('dotenv').config();

// -------------------------
// Import Required Modules
// -------------------------
const fs = require('fs');
const https = require('https');
const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const passport = require('passport');
const GitHubStrategy = require('passport-github2').Strategy;
const axios = require('axios');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis').default || require('rate-limit-redis');
const Redis = require('ioredis');
const cors = require('cors');
const util = require('util');
const { exec } = require('child_process');
const execAsync = util.promisify(exec);
const winston = require('winston');
const Greenlock = require('greenlock-express');
const constants = require('constants');  // for secureOptions
const pathModule = require('path');

// -------------------------
// Create Express App
// -------------------------
const app = express();

// -------------------------
// Logger Setup with Winston
// -------------------------
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json() // Use JSON format for production logging
  ),
  transports: [
    new winston.transports.Console(),
    // Optionally, log to a file:
    // new winston.transports.File({ filename: 'logs/production.log' })
  ]
});

// -------------------------
// Security Middleware
// -------------------------
app.use(helmet({
  hsts: {
    maxAge: 31536000,         // 1 year in seconds
    includeSubDomains: true,
    preload: true
  },
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"]
      // Further CSP directives as needed
    }
  }
}));

app.use(bodyParser.json());
const allowedOrigins = process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : [];
app.use(cors({ origin: allowedOrigins, credentials: true }));

// -------------------------
// Rate Limiting
// -------------------------
const redisClient = new Redis(process.env.REDIS_URL);
app.use(rateLimit({
  store: new RedisStore({
    sendCommand: (...args) => redisClient.call(...args)
  }),
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: { error: 'Too many requests from this IP, please try again after 15 minutes.' }
}));

// -------------------------
// Session Management
// -------------------------
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax'
  }
}));

// -------------------------
// Passport Initialization
// -------------------------
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
  done(null, user.id); // Store the MongoDB _id
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// -------------------------
// MongoDB Connection & User Model
// -------------------------
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});
mongoose.connection.on('error', (err) => {
  logger.error('MongoDB connection error:', { error: err });
});
mongoose.connection.once('open', () => {
  logger.info('Connected to MongoDB');
});

const userSchema = new mongoose.Schema({
  githubId: { type: String, required: true, unique: true },
  username: String,
  subscription: { type: String, default: 'free' },
  usage: { type: Number, default: 0 },
  lastReset: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

// -------------------------
// Passport GitHub Strategy
// -------------------------
passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: process.env.GITHUB_CALLBACK_URL
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await User.findOne({ githubId: profile.id });
      if (!user) {
        user = await User.create({
          githubId: profile.id,
          username: profile.username,
          subscription: 'free',
          usage: 0,
          lastReset: new Date()
        });
      } else {
        user.username = profile.username;
        await user.save();
      }
      return done(null, user);
    } catch (error) {
      logger.error('Error in GitHubStrategy:', { error: error.message });
      return done(error);
    }
  }
));

// -------------------------
// Authentication Routes
// -------------------------
app.get('/auth/github',
  passport.authenticate('github', { scope: ['user:email'] })
);

app.get('/auth/github/callback',
  passport.authenticate('github', { failureRedirect: '/' }),
  (req, res) => {
    res.redirect('/dashboard');
  }
);

// -------------------------
// Middleware: Ensure Authentication
// -------------------------
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.status(401).json({ error: 'Unauthorized – please log in via GitHub.' });
}

// -------------------------
// Helper: Check & Reset Monthly Usage
// -------------------------
async function checkUsage(user) {
  const now = new Date();
  if (
    now.getMonth() !== user.lastReset.getMonth() ||
    now.getFullYear() !== user.lastReset.getFullYear()
  ) {
    user.usage = 0;
    user.lastReset = now;
    await user.save();
  }
}

// -------------------------
// Functions for Repomix Integration
// -------------------------
async function runRepomix(repoUrl) {
  const match = repoUrl.match(/github\.com\/([^\/]+)\/([^\/]+)(\/|$)/);
  if (!match) {
    throw new Error("Invalid GitHub repository URL.");
  }
  const owner = match[1];
  const repo = match[2].replace(/\.git$/, '');
  const repoDir = pathModule.join(__dirname, "temp_repos", `${owner}_${repo}`);
  try {
    const tempReposDir = pathModule.join(__dirname, "temp_repos");
    if (!fs.existsSync(tempReposDir)) {
      fs.mkdirSync(tempReposDir, { recursive: true });
    }
    if (fs.existsSync(repoDir)) {
      console.log(`Deleting existing directory: ${repoDir}`);
      fs.rmSync(repoDir, { recursive: true, force: true });
    }
    console.log(`Cloning repository: ${repoUrl} into ${repoDir}`);
    await execAsync(`git clone --depth=1 ${repoUrl} ${repoDir}`);
    console.log(`Running Repomix on ${repoDir} without colorization`);
    const { stdout, stderr } = await execAsync(`repomix ${repoDir}`, {
      env: { ...process.env, NO_COLOR: '1' }
    });
    if (stderr && stderr.trim() !== "") {
      console.error("Repomix stderr:", stderr);
      throw new Error(stderr);
    }
    const parsedData = parseRepomixOutput(stdout);
    console.log(`Deleting cloned repository: ${repoDir}`);
    fs.rmSync(repoDir, { recursive: true, force: true });
    return parsedData;
  } catch (error) {
    console.error("Error running repomix:", error);
    throw error;
  }
}

function parseRepomixOutput(output) {
  const lines = output.split("\n");
  let summary = "";
  let securityCheck = "";
  for (let line of lines) {
    if (line.includes("📈 Top 5 Files by Character Count")) {
      summary += line + "\n";
    }
    if (line.includes("🔎 Security Check:")) {
      securityCheck = line;
    }
  }
  return {
    summary: summary.trim(),
    security: securityCheck.trim(),
    rawOutput: output.trim()
  };
}

// -------------------------
// Summarization Endpoint
// -------------------------
app.post('/summarize', ensureAuthenticated, async (req, res, next) => {
  try {
    const { repoUrl } = req.body;
    if (!repoUrl) {
      return res.status(400).json({ error: 'repoUrl is required in the request body.' });
    }
    const user = req.user;
    await checkUsage(user);
    const usageLimit = user.subscription === 'paid' ? 500 : 5;
    if (user.usage >= usageLimit) {
      return res.status(429).json({ error: 'Monthly summary limit reached. Upgrade or wait until next month.' });
    }
    const match = repoUrl.match(/github\.com\/([^\/]+)\/([^\/]+)(\/|$)/);
    if (!match) {
      return res.status(400).json({ error: 'Invalid GitHub repository URL.' });
    }
    const repomixData = await runRepomix(repoUrl);
    const prompt = `
Given the following repository analysis data:
${JSON.stringify(repomixData, null, 2)}
Please provide a detailed summary, highlight key design choices, analyze the code structure, and flag any potential security concerns.
    `;
    const model = user.subscription === 'paid' ? 'gpt-4' : 'gpt-3.5-turbo';
    const openaiResponse = await axios.post(
      'https://api.openai.com/v1/chat/completions',
      {
        model,
        messages: [{ role: "user", content: prompt }]
      },
      {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${process.env.OPENAI_API_KEY}`,
        }
      }
    );
    const summary = openaiResponse.data.choices[0].message.content;
    user.usage += 1;
    await user.save();
    res.json({
      summary,
      repomixData,
    });
  } catch (error) {
    console.error('Error during summarization:', error);
    next(error);
  }
});

// -------------------------
// File Tree Endpoint
// -------------------------
app.get('/filetree', ensureAuthenticated, async (req, res, next) => {
  try {
    const { repoUrl, branch } = req.query;
    if (!repoUrl) {
      return res.status(400).json({ error: 'repoUrl is required as a query parameter.' });
    }
    const match = repoUrl.match(/github\.com\/([^\/]+)\/([^\/]+)(\/|$)/);
    if (!match) {
      return res.status(400).json({ error: 'Invalid GitHub repository URL.' });
    }
    const owner = match[1];
    const repo = match[2].replace(/\.git$/, '');
    const targetBranch = branch || 'main';
    const treeUrl = `https://api.github.com/repos/${owner}/${repo}/git/trees/${targetBranch}?recursive=1`;
    const githubResponse = await axios.get(treeUrl, {
      headers: { 'Accept': 'application/vnd.github.v3+json' }
    });
    const tree = githubResponse.data.tree;
    res.json({ tree });
  } catch (err) {
    console.error('Error fetching file tree:', err);
    next(err);
  }
});

// -------------------------
// Dashboard Endpoint
// -------------------------
app.get('/dashboard', ensureAuthenticated, (req, res) => {
  res.send(`Hello, ${req.user.username}. You have used ${req.user.usage} summaries this month.`);
});

// -------------------------
// Global Error-Handling Middleware
// -------------------------
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.stack);
  const status = err.status || 500;
  res.status(status).json({
    error: err.message || 'Internal Server Error'
  });
});

// -------------------------
// Start the Server (HTTP is handled by Greenlock)
// -------------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`GITSUM backend listening on port ${PORT}`);
});
