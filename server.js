require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "development-secret-change-this";

const corsOrigins = process.env.CORS_ORIGINS
  ? process.env.CORS_ORIGINS.split(",").map((origin) => origin.trim())
  : ["*"];

app.use(helmet());
app.use(express.json({ limit: "1mb" }));

app.use(
  cors({
    origin: corsOrigins.includes("*") ? true : corsOrigins,
    credentials: true
  })
);

app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 300,
    standardHeaders: true,
    legacyHeaders: false
  })
);

const io = new Server(server, {
  cors: {
    origin: corsOrigins.includes("*") ? true : corsOrigins,
    credentials: true
  }
});

/* =========================
   MONGODB
========================= */

let databaseConnected = false;

if (process.env.MONGODB_URI) {
  mongoose
    .connect(process.env.MONGODB_URI)
    .then(() => {
      databaseConnected = true;
      console.log("MongoDB connected");
    })
    .catch((error) => {
      console.error("MongoDB connection failed:", error.message);
    });
} else {
  console.log("MONGODB_URI is not configured.");
}

/* =========================
   SCHEMAS
========================= */

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true
    },

    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true
    },

    password: {
      type: String,
      required: true
    },

    role: {
      type: String,
      enum: ["student", "admin", "owner"],
      default: "student"
    },

    xp: {
      type: Number,
      default: 0
    },

    level: {
      type: Number,
      default: 1
    },

    premium: {
      type: Boolean,
      default: false
    }
  },
  {
    timestamps: true
  }
);

const threatSchema = new mongoose.Schema(
  {
    title: String,
    description: String,
    severity: {
      type: String,
      enum: ["low", "medium", "high", "critical"],
      default: "medium"
    },

    category: String,

    reportedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User"
    },

    status: {
      type: String,
      enum: ["open", "investigating", "resolved"],
      default: "open"
    }
  },
  {
    timestamps: true
  }
);

const User = mongoose.model("User", userSchema);
const Threat = mongoose.model("Threat", threatSchema);

/* =========================
   HELPERS
========================= */

function createToken(user) {
  return jwt.sign(
    {
      id: user._id.toString(),
      role: user.role
    },
    JWT_SECRET,
    {
      expiresIn: "7d"
    }
  );
}

function authenticate(req, res, next) {
  const header = req.headers.authorization;

  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({
      success: false,
      message: "Authentication required."
    });
  }

  const token = header.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    req.user = decoded;

    next();
  } catch {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired token."
    });
  }
}

function requireAdmin(req, res, next) {
  if (!["admin", "owner"].includes(req.user.role)) {
    return res.status(403).json({
      success: false,
      message: "Administrator access required."
    });
  }

  next();
}

/* =========================
   HEALTH
========================= */

app.get("/", (req, res) => {
  res.json({
    success: true,
    platform: "CyberShield Student",
    message: "CyberShield backend is running.",
    database: databaseConnected ? "connected" : "not connected",
    timestamp: new Date().toISOString()
  });
});

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    backend: "online",
    database: databaseConnected ? "connected" : "not connected"
  });
});

/* =========================
   AUTH
========================= */

app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "Name, email and password are required."
      });
    }

    if (!databaseConnected) {
      return res.status(503).json({
        success: false,
        message: "Database is not connected yet."
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        success: false,
        message: "Password must contain at least 8 characters."
      });
    }

    const normalizedEmail = email.toLowerCase().trim();

    const existingUser = await User.findOne({
      email: normalizedEmail
    });

    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: "An account with this email already exists."
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const user = await User.create({
      name: name.trim(),
      email: normalizedEmail,
      password: hashedPassword
    });

    const token = createToken(user);

    res.status(201).json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        xp: user.xp,
        level: user.level,
        premium: user.premium
      }
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: "Registration failed."
    });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email and password are required."
      });
    }

    if (!databaseConnected) {
      return res.status(503).json({
        success: false,
        message: "Database is not connected yet."
      });
    }

    const user = await User.findOne({
      email: email.toLowerCase().trim()
    });

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password."
      });
    }

    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password."
      });
    }

    const token = createToken(user);

    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        xp: user.xp,
        level: user.level,
        premium: user.premium
      }
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: "Login failed."
    });
  }
});

/* =========================
   USER PROFILE
========================= */

app.get("/api/me", authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found."
      });
    }

    res.json({
      success: true,
      user
    });
  } catch {
    res.status(500).json({
      success: false,
      message: "Could not load profile."
    });
  }
});

/* =========================
   THREAT REPORTING
========================= */

app.post("/api/threats", authenticate, async (req, res) => {
  try {
    if (!databaseConnected) {
      return res.status(503).json({
        success: false,
        message: "Database is not connected yet."
      });
    }

    const { title, description, severity, category } = req.body;

    if (!title || !description) {
      return res.status(400).json({
        success: false,
        message: "Title and description are required."
      });
    }

    const threat = await Threat.create({
      title,
      description,
      severity: severity || "medium",
      category: category || "other",
      reportedBy: req.user.id
    });

    io.emit("new-threat", {
      id: threat._id,
      title: threat.title,
      severity: threat.severity,
      status: threat.status
    });

    res.status(201).json({
      success: true,
      threat
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: "Threat report failed."
    });
  }
});

/* =========================
   ADMIN
========================= */

app.get(
  "/api/admin/threats",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const threats = await Threat.find()
        .populate("reportedBy", "name email")
        .sort({ createdAt: -1 });

      res.json({
        success: true,
        threats
      });
    } catch {
      res.status(500).json({
        success: false,
        message: "Could not load threats."
      });
    }
  }
);

app.patch(
  "/api/admin/threats/:id",
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const { status } = req.body;

      const threat = await Threat.findByIdAndUpdate(
        req.params.id,
        { status },
        { new: true }
      );

      if (!threat) {
        return res.status(404).json({
          success: false,
          message: "Threat not found."
        });
      }

      io.emit("threat-updated", threat);

      res.json({
        success: true,
        threat
      });
    } catch {
      res.status(500).json({
        success: false,
        message: "Could not update threat."
      });
    }
  }
);

/* =========================
   SOCKET.IO
========================= */

io.on("connection", (socket) => {
  console.log("CyberShield client connected:", socket.id);

  socket.on("disconnect", () => {
    console.log("CyberShield client disconnected:", socket.id);
  });
});

/* =========================
   404
========================= */

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "CyberShield API route not found."
  });
});

/* =========================
   START SERVER
========================= */

server.listen(PORT, "0.0.0.0", () => {
  console.log(`CyberShield backend running on port ${PORT}`);
});
