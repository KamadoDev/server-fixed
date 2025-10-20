// server.js (CommonJS) - secure Express server with dynamic CSP (nonce)
require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const mongoSanitize = require("express-mongo-sanitize");
const xss = require("xss-clean");
const hpp = require("hpp");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const morgan = require("morgan");

const app = express();

/* ---------------------------
   Basic setup
   --------------------------- */
app.use(express.json({ limit: "10kb" }));
app.use(cookieParser());
app.disable("x-powered-by"); // hide framework
app.set("etag", false); // avoid ETag timestamp disclosure

// Logging in dev
if (process.env.NODE_ENV !== "production") {
  app.use(morgan("dev"));
}

/* ---------------------------
   Security middlewares (non-CSP)
   --------------------------- */
app.use(mongoSanitize()); // prevent Mongo operator injection
app.use(xss()); // basic XSS cleaning
app.use(hpp()); // HTTP parameter pollution protection

// Helmet useful features (disable CSP here because we set CSP manually below)
app.use(helmet.hidePoweredBy());
app.use(helmet.noSniff());
app.use(helmet.frameguard({ action: "deny" }));
// Note: helmet.xssFilter() is deprecated in newer Helmet; included if available
if (helmet.xssFilter) {
  app.use(helmet.xssFilter());
}

// HSTS - enable in production (requires serving via HTTPS)
if (process.env.NODE_ENV === "production") {
  app.use(
    helmet.hsts({
      maxAge: 31536000, // 1 year
      includeSubDomains: true,
      preload: true,
    })
  );
}

/* ---------------------------
   CORS - whitelist
   --------------------------- */
const allowedOrigins = [
  "https://runshop.netlify.app",
  "https://runshop-admin.netlify.app",
  // add more trusted origins here
];

app.use(
  cors({
    origin: function (origin, callback) {
      // allow non-browser tools (curl, server-to-server) when origin is undefined
      if (!origin || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      console.warn("Blocked CORS request from:", origin);
      return callback(new Error("Not allowed by CORS"));
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

/* ---------------------------
   Rate limiter
   --------------------------- */
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // max requests per window per IP
    standardHeaders: true,
    legacyHeaders: false,
    message: "Too many requests, please try again later.",
  })
);

/* ---------------------------
   Dynamic CSP middleware (nonce per response)
   - No 'unsafe-inline' and no 'unsafe-eval'
   - If you need inline script, include nonce in templates or server-injected HTML.
   --------------------------- */
app.use((req, res, next) => {
  // generate nonce for this response (base64)
  const nonce = crypto.randomBytes(16).toString("base64");
  res.locals.cspNonce = nonce; // available for templates or manual injection

  // build directives; edit domains as needed
  const scriptSrc = [
    "'self'",
    `'nonce-${nonce}'`, // allows inline scripts that include this nonce
    "https://www.googletagmanager.com",
    "https://ssl.google-analytics.com",
  ];

  const styleSrc = [
    "'self'",
    `'nonce-${nonce}'`, // allows inline styles with same nonce
    "https://fonts.googleapis.com",
  ];

  const connectSrc = [
    "'self'",
    "https://runshop.netlify.app",
    "https://runshop-admin.netlify.app",
    "https://www.google-analytics.com",
    // include localhost only on development
    ...(process.env.NODE_ENV !== "production" ? ["http://localhost:4000"] : []),
  ];

  const imgSrc = [
    "'self'",
    "data:",
    `https://res.cloudinary.com/${process.env.CLOUDINARY_NAME || ""}/`,
  ];

  const fontSrc = ["'self'", "https://fonts.gstatic.com"];

  // join directives into a header string
  const directives = [
    `default-src 'self'`,
    `script-src ${scriptSrc.join(" ")}`,
    `style-src ${styleSrc.join(" ")}`,
    `img-src ${imgSrc.join(" ")}`,
    `font-src ${fontSrc.join(" ")}`,
    `connect-src ${connectSrc.join(" ")}`,
    `object-src 'none'`,
    `frame-ancestors 'none'`,
    `form-action 'self'`,
    `base-uri 'self'`,
    `upgrade-insecure-requests`,
  ];

  const cspHeaderValue = directives.join("; ");

  // Use Report-Only during initial rollout if desired
  if (process.env.CSP_REPORT_ONLY === "true") {
    res.setHeader("Content-Security-Policy-Report-Only", cspHeaderValue);
  } else {
    res.setHeader("Content-Security-Policy", cspHeaderValue);
  }

  next();
});

/* ---------------------------
   Routes (load your route modules)
   --------------------------- */
const routes = {
  user: require("./routes/userRoutes"),
  cart: require("./routes/cartRoutes"),
  category: require("./routes/categoriesRoutes"),
  subCategory: require("./routes/subCategoriesRoutes"),
  products: require("./routes/productsRoutes"),
  voucher: require("./routes/voucherRoutes"),
  favorite: require("./routes/favoriteProductRoutes"),
  review: require("./routes/reviewRoutes"),
  order: require("./routes/orderRoutes"),
  slideBanner: require("./routes/slideBannerRoutes"),
  search: require("./routes/searchRoutes"),
  contact: require("./routes/contactRoutes"),
  logoWeb: require("./routes/logoWebRoutes"),
};

for (const [key, route] of Object.entries(routes)) {
  app.use(`/api/${key}`, route);
}

/* ---------------------------
   Simple health / root route (demo)
   --------------------------- */
app.get("/", (req, res) => {
  // if you render templates you can use res.locals.cspNonce inside HTML
  res.send("✅ Server is running and security headers are applied");
});

/* ---------------------------
   Error handling middleware
   --------------------------- */
app.use((err, req, res, next) => {
  console.error("Error:", err.message || err);
  if (err.message === "Not allowed by CORS") {
    return res.status(403).json({ success: false, message: "Origin not allowed by CORS" });
  }
  res.status(err.status || 500).json({
    success: false,
    message: err.message || "Internal Server Error",
  });
});

/* ---------------------------
   MongoDB connection and start server
   --------------------------- */
const PORT = process.env.PORT || 4000;
mongoose
  .connect(process.env.CONNECTION_STRING, {
    // options can go here
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("✅ MongoDB connected");
    app.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT} (NODE_ENV=${process.env.NODE_ENV})`);
    });
  })
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err);
    process.exit(1);
  });

module.exports = app;
