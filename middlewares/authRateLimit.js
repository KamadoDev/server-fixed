const rateLimit = require("express-rate-limit");

exports.authLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 phút
  max: 5, // tối đa 5 request/phút
  message: {
    success: false,
    message: "Quá nhiều yêu cầu đăng nhập. Vui lòng thử lại sau 1 phút.",
  },
});
