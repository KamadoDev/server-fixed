// ---------------------------
// 🔒 Secure Express Server (Tối ưu bảo mật CSP, ZAP friendly)
// ---------------------------
const express = require("express");
const mongoose = require("mongoose");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const mongoSanitize = require("express-mongo-sanitize");
const xss = require("xss-clean");
const hpp = require("hpp");
const cookieParser = require("cookie-parser");
const morgan = require("morgan");
require("dotenv").config();

const app = express();

// ---------------------------
// 📦 Middleware cơ bản
// ---------------------------
app.use(express.json({ limit: "10kb" }));
app.use(cookieParser());
app.use(xss());
app.use(hpp());
app.disable("x-powered-by");

if (process.env.NODE_ENV !== "production") {
  app.use(morgan("dev"));
}

// ---------------------------
// 🌐 Cấu hình CORS an toàn
// ---------------------------
const allowedOrigins = [
  "http://localhost:3000",
  "http://localhost:5173",
  "https://runshop-fixed.netlify.app",
  "https://runshop-admin-fixed.netlify.app",
];

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.warn("❌ Blocked CORS request from:", origin);
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true,
};
app.use(cors(corsOptions));
app.options("*", cors(corsOptions));

// ---------------------------
// 🧱 Helmet bảo mật nâng cao
// ---------------------------
app.use(
  helmet({
    crossOriginEmbedderPolicy: true,
    crossOriginOpenerPolicy: { policy: "same-origin" },
    crossOriginResourcePolicy: { policy: "same-origin" },
    hidePoweredBy: true,
    noSniff: true,
    frameguard: { action: "deny" },
    referrerPolicy: { policy: "no-referrer" },
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
          "'self'",
          "https://www.googletagmanager.com",
          "https://ssl.google-analytics.com",
        ],
        styleSrc: [
          "'self'",
          "https://fonts.googleapis.com",
        ],
        imgSrc: [
          "'self'",
          "data:",
          `https://res.cloudinary.com/${process.env.CLOUDINARY_NAME}/`,
        ],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        connectSrc: [
          "'self'",
          "https://runshop-fixed.netlify.app",
          "https://runshop-admin-fixed.netlify.app",
          "http://localhost:4000",
        ],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        upgradeInsecureRequests: [],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
  })
);

// ---------------------------
// 🧩 Bảo vệ bổ sung
// ---------------------------
app.use(mongoSanitize());
app.use(
  rateLimit({
    windowMs: 60 * 1000, // 1 phút
    max: 100,
    message: "Too many requests, please try again later.",
  })
);

// ---------------------------
// 📦 Routes
// ---------------------------
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

// ---------------------------
// ⚙️ Xử lý lỗi toàn cục
// ---------------------------
app.use((err, req, res, next) => {
  console.error("Error:", err.message);
  res.status(500).json({
    success: false,
    message: "Internal server error",
  });
});

// ---------------------------
// 🗄️ Kết nối MongoDB
// ---------------------------
mongoose
  .connect(process.env.CONNECTION_STRING)
  .then(() => {
    console.log("✅ Đã kết nối cơ sở dữ liệu MongoDB");
    app.listen(process.env.PORT, () => {
      console.log(`🚀 Server đang chạy tại http://localhost:${process.env.PORT}`);
    });
  })
  .catch((err) => {
    console.error("❌ Lỗi kết nối cơ sở dữ liệu:", err);
  });
