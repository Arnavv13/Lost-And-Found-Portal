
require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// Temporary OTP storage. OTPs expire after 5 minutes.
const otpStore = new Map();

if (!process.env.MONGODB_URI) {
  throw new Error("Set MONGODB_URI in .env");
}

if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
  throw new Error("Set JWT_SECRET (32+ characters) in .env");
}

for (const key of [
  "SMTP_HOST",
  "SMTP_PORT",
  "SMTP_USER",
  "SMTP_PASS",
  "MAIL_FROM"
]) {
  if (!process.env[key]) {
    throw new Error(`Missing ${key} in .env`);
  }
}

// ======================================
// DATABASE CONNECTION
// ======================================

mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("MongoDB connected successfully"))
  .catch(error => {
    console.error("MongoDB connection failed:", error.message);
    process.exit(1);
  });

// ======================================
// USER MODEL
// ======================================

const userSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: true,
    trim: true,
    maxlength: 40
  },
  lastName: {
    type: String,
    required: true,
    trim: true,
    maxlength: 40
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    maxlength: 254
  },
  phone: {
    type: String,
    required: true,
    trim: true,
    maxlength: 20
  },
  password: {
    type: String,
    required: true
  }
}, { timestamps: true });

const User = mongoose.model("User", userSchema);

// ======================================
// ITEM MODEL
// ======================================

const itemSchema = new mongoose.Schema({
  ownerEmail: {
    type: String,
    required: true,
    index: true,
    lowercase: true
  },
  type: {
    type: String,
    enum: ["lost", "found"],
    required: true
  },
  name: {
    type: String,
    required: true,
    trim: true,
    maxlength: 60
  },
  location: {
    type: String,
    required: true,
    trim: true,
    maxlength: 60
  },
  date: {
    type: String,
    required: true
  },
  contact: {
    type: String,
    required: true,
    trim: true,
    maxlength: 60
  },
  desc: {
    type: String,
    trim: true,
    maxlength: 200,
    default: ""
  },
  image: {
    type: String,
    default: "",
    maxlength: 1500000
  },
  resolved: {
    type: Boolean,
    default: false
  }
}, { timestamps: true });

const Item = mongoose.model("Item", itemSchema);

// ======================================
// EMAIL CONFIGURATION
// ======================================

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  secure: Number(process.env.SMTP_PORT) === 465,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});
transporter.verify()
  .then(() => {
    console.log("SMTP connection successful!");
  })
  .catch((error) => {
    console.error("SMTP connection failed:", error);
  });
// ======================================
// MIDDLEWARE
// ======================================

app.use(express.json({ limit: "2mb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const phonePattern = /^\+?[0-9\s()-]{7,20}$/;

const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { message: "Too many OTP requests. Try again later." }
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { message: "Too many login attempts. Try again later." }
});

const verifyLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { message: "Too many verification attempts. Try again later." }
});

function hashOtp(otp) {
  return crypto.createHash("sha256").update(otp).digest("hex");
}

// ======================================
// AUTHENTICATION HELPERS
// ======================================

function setSession(res, user) {
  const token = jwt.sign(
    {
      userId: user._id.toString(),
      email: user.email
    },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );

  res.cookie("lnf_session", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
}

function requireAuth(req, res, next) {
  try {
    const token = req.cookies.lnf_session;

    if (!token) {
      return res.status(401).json({
        message: "Please sign in again."
      });
    }

    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();

  } catch {
    res.clearCookie("lnf_session");

    return res.status(401).json({
      message: "Your session expired. Please sign in again."
    });
  }
}

function publicUser(user) {
  return {
    firstName: user.firstName,
    lastName: user.lastName,
    email: user.email,
    phone: user.phone
  };
}

// ======================================
// REGISTER: REQUEST EMAIL OTP
// ======================================

app.post("/api/auth/register/request-otp", otpLimiter, async (req, res) => {
  try {
    const firstName = String(req.body.firstName || "").trim();
    const lastName = String(req.body.lastName || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const phone = String(req.body.phone || "").trim();
    const password = String(req.body.password || "");

    if (
      !firstName ||
      !lastName ||
      !emailPattern.test(email) ||
      email.length > 254 ||
      !phonePattern.test(phone) ||
      password.length < 8 ||
      password.length > 72
    ) {
      return res.status(400).json({
        message: "Enter valid details. Password must be at least 8 characters."
      });
    }

    if (firstName.length > 40 || lastName.length > 40) {
      return res.status(400).json({
        message: "Name must be within 40 characters."
      });
    }

    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(409).json({
        message: "This email is already registered. Please log in."
      });
    }

    const old = otpStore.get(email);

    if (old && Date.now() - old.createdAt < 60000) {
      return res.status(429).json({
        message: "Wait 60 seconds before requesting another code."
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const otp = crypto.randomInt(100000, 1000000).toString();

    otpStore.set(email, {
      hash: hashOtp(otp),
      createdAt: Date.now(),
      expiresAt: Date.now() + 5 * 60 * 1000,
      attempts: 0,
      details: {
        firstName,
        lastName,
        email,
        phone,
        password: hashedPassword
      }
    });

    try {
      await transporter.sendMail({
        from: process.env.MAIL_FROM,
        to: email,
        subject: "Verify your Lost & Found Portal account",
        text: `Hello ${firstName},

Your registration verification code is ${otp}.

This code expires in 5 minutes.
Do not share this code with anyone.

Lost & Found Portal`
      });

      res.json({
        message: "OTP sent to your email. Please verify to create your account."
      });

    } catch (error) {
      otpStore.delete(email);

      console.error("Email delivery error:", error.message);

      res.status(502).json({
        message: "Could not send OTP. Check your email configuration."
      });
    }

  } catch (error) {
    console.error("Registration OTP error:", error);

    res.status(500).json({
      message: "Could not start registration."
    });
  }
});

// ======================================
// REGISTER: VERIFY OTP AND CREATE USER
// ======================================

app.post("/api/auth/register/verify-otp", verifyLimiter, async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const otp = String(req.body.otp || "").trim();

    if (!emailPattern.test(email) || !/^\d{6}$/.test(otp)) {
      return res.status(400).json({
        message: "Enter a valid email and 6-digit OTP."
      });
    }

    const record = otpStore.get(email);

    if (!record) {
      return res.status(400).json({
        message: "Request a new OTP."
      });
    }

    if (Date.now() > record.expiresAt) {
      otpStore.delete(email);

      return res.status(400).json({
        message: "OTP expired. Request a new one."
      });
    }

    record.attempts += 1;

    if (record.attempts > 5) {
      otpStore.delete(email);

      return res.status(429).json({
        message: "Too many incorrect attempts. Register again."
      });
    }

    const supplied = Buffer.from(hashOtp(otp), "hex");
    const expected = Buffer.from(record.hash, "hex");

    if (!crypto.timingSafeEqual(supplied, expected)) {
      return res.status(400).json({
        message: "Incorrect OTP. Try again."
      });
    }

    const existingUser = await User.findOne({ email });

    if (existingUser) {
      otpStore.delete(email);

      return res.status(409).json({
        message: "This email is already registered. Please log in."
      });
    }

    const user = await User.create(record.details);

    otpStore.delete(email);

    setSession(res, user);

    res.status(201).json({
      message: "Registration successful!",
      user: publicUser(user)
    });

  } catch (error) {
    console.error("OTP verification error:", error);

    res.status(500).json({
      message: "Could not verify OTP or create account."
    });
  }
});

// ======================================
// LOGIN: EMAIL + PASSWORD
// ======================================

app.post("/api/auth/login", loginLimiter, async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!emailPattern.test(email) || !password) {
      return res.status(400).json({
        message: "Enter your registered email and password."
      });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(401).json({
        message: "Invalid email or password."
      });
    }

    const passwordMatches = await bcrypt.compare(
      password,
      user.password
    );

    if (!passwordMatches) {
      return res.status(401).json({
        message: "Invalid email or password."
      });
    }

    setSession(res, user);

    res.json({
      message: "Login successful!",
      user: publicUser(user)
    });

  } catch (error) {
    console.error("Login error:", error);

    res.status(500).json({
      message: "Could not log in."
    });
  }
});

// ======================================
// CHECK LOGIN SESSION
// ======================================

app.get("/api/auth/me", requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select("-password");

    if (!user) {
      res.clearCookie("lnf_session");

      return res.status(401).json({
        authenticated: false
      });
    }

    res.json({
      authenticated: true,
      user: publicUser(user)
    });

  } catch {
    res.status(500).json({
      message: "Could not check session."
    });
  }
});

// ======================================
// LOGOUT
// ======================================

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("lnf_session", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict"
  });

  res.json({
    message: "Signed out successfully."
  });
});

// ======================================
// LOST & FOUND ITEMS API
// ======================================

app.get("/api/items", requireAuth, async (req, res) => {
  try {
    const items = await Item.find({
      ownerEmail: req.user.email
    })
      .sort({ createdAt: -1 })
      .lean();

    res.json({ items });

  } catch {
    res.status(500).json({
      message: "Could not load items."
    });
  }
});

app.post("/api/items", requireAuth, async (req, res) => {
  try {
    const {
      type,
      name,
      location,
      date,
      contact,
      desc = "",
      image = ""
    } = req.body;

    if (
      !["lost", "found"].includes(type) ||
      !name?.trim() ||
      !location?.trim() ||
      !date ||
      !contact?.trim()
    ) {
      return res.status(400).json({
        message: "Please complete all required fields."
      });
    }

    if (
      image &&
      (
        !String(image).startsWith("data:image/") ||
        String(image).length > 1500000
      )
    ) {
      return res.status(400).json({
        message: "Image is invalid or too large."
      });
    }

    const item = await Item.create({
      ownerEmail: req.user.email,
      type,
      name,
      location,
      date,
      contact,
      desc,
      image,
      resolved: false
    });

    res.status(201).json({ item });

  } catch (error) {
    console.error("Create item error:", error);

    res.status(500).json({
      message: "Could not save the item."
    });
  }
});

app.patch("/api/items/:id", requireAuth, async (req, res) => {
  try {
    const item = await Item.findOneAndUpdate(
      {
        _id: req.params.id,
        ownerEmail: req.user.email
      },
      {
        $set: {
          resolved: Boolean(req.body.resolved)
        }
      },
      {
        new: true,
        runValidators: true
      }
    );

    if (!item) {
      return res.status(404).json({
        message: "Item not found."
      });
    }

    res.json({ item });

  } catch {
    res.status(400).json({
      message: "Invalid item ID or update."
    });
  }
});

app.delete("/api/items/:id", requireAuth, async (req, res) => {
  try {
    const item = await Item.findOneAndDelete({
      _id: req.params.id,
      ownerEmail: req.user.email
    });

    if (!item) {
      return res.status(404).json({
        message: "Item not found."
      });
    }

    res.json({
      message: "Item deleted."
    });

  } catch {
    res.status(400).json({
      message: "Invalid item ID."
    });
  }
});

// ======================================
// START SERVER
// ======================================

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
