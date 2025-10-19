const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const validator = require("validator");
require("dotenv").config();

// Kiểm tra email hợp lệ
const isValidEmail = (email) => {
  return validator.isEmail(email);
};
const isValidPhone = (phone) => {
  return validator.isMobilePhone(phone, "vi-VN"); // Kiểm tra định dạng số điện thoại Việt Nam
};
// Kiểm tra độ dài mật khẩu hợp lệ
const isValidPassword = (password) => {
  const errors = [];
  const minLength = 8;

  if (password.length < minLength) {
    errors.push(`Mật khẩu phải chứa ít nhất ${minLength} ký tự.`);
  }
  if (!/[A-Z]/.test(password)) {
    errors.push("Mật khẩu phải chứa ít nhất một chữ cái viết hoa.");
  }
  if (!/[a-z]/.test(password)) {
    errors.push("Mật khẩu phải chứa ít nhất một chữ cái viết thường.");
  }
  if (!/[0-9]/.test(password)) {
    errors.push("Mật khẩu phải chứa ít nhất một chữ số.");
  }
  if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    errors.push("Mật khẩu phải chứa ít nhất một ký tự đặc biệt (!@#$%^&*...).");
  }

  return errors;
};

// Xử lý lỗi
const handleError = (res, error) => {
  console.error(error);
  return res.status(500).json({
    success: false,
    message: "Internal server error",
    error: error.message,
  });
};

// Mã hóa mật khẩu
const hashPassword = async (password) => {
  const saltRounds = 10;
  return await bcrypt.hash(password, saltRounds);
};

// Kiểm tra mật khẩu
const checkPassword = async (password, hashedPassword) => {
  return await bcrypt.compare(password, hashedPassword);
};

// Tạo JWT token
const generateToken = (user) => {
  const expirationTime = user.rememberMe
    ? "7d"
    : process.env.TOKEN_EXPIRATION || "1h"; // Nếu rememberMe là true thì hết hạn sau 7 ngày, ngược lại dùng giá trị mặc định 1 giờ

  return jwt.sign(
    { id: user._id, username: user.username, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: expirationTime } // Sử dụng expirationTime tùy theo rememberMe
  );
};

// Xác thực JWT token
// const verifyToken = (req, res, next) => {
//   const token = req.headers.authorization?.split(" ")[1]; // Lấy token từ header Authorization
//   console.log("Token received: ", token); // In token ra để kiểm tra
//   if (!token) {
//     return res.status(403).json({
//       success: false,
//       message: "Vui lòng đăng nhập!",
//       type: "error",
//     });
//   }

//   try {
//     // Giải mã token
//     const decoded = jwt.verify(token, process.env.JWT_SECRET);
//     req.user = decoded; // Lưu thông tin người dùng vào req.user
//     console.log(decoded); //
//     next(); // Tiếp tục với các middleware hoặc route handler tiếp theo
//   } catch (error) {
//     return res.status(401).json({
//       success: false,
//       message: "Phiên đăng nhập không hợp lệ!",
//     });
//   }
// };

// Xác thực JWT token
const verifyToken = (req, res, next) => {
  // ✨ BƯỚC 1: Ưu tiên lấy token từ HTTP-only Cookie
  const tokenFromCookie = req.cookies.token; 
  
  // BƯỚC 2: Nếu không có trong cookie, thử lấy từ header Authorization (cách cũ/fallback)
  const tokenFromHeader = req.headers.authorization?.split(" ")[1];
  
  // BƯỚC 3: Chọn token (Ưu tiên Cookie)
  const token = tokenFromCookie || tokenFromHeader;

  // console.log("Token received: ", token); // Tắt console.log này để giữ tính bảo mật

  if (!token) {
    return res.status(401).json({ // Đổi 403 thành 401 vì đây là lỗi xác thực
      success: false,
      message: "Vui lòng đăng nhập!",
      type: "error",
    });
  }

  try {
    // Giải mã token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // Lưu thông tin người dùng vào req.user
    // console.log(decoded); // Tắt console.log này
    next(); // Tiếp tục
  } catch (error) {
    // Xóa cookie token nếu nó không hợp lệ/hết hạn
    res.clearCookie("token", {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: process.env.NODE_ENV === "production" ? "None" : "Lax",
    });
    return res.status(401).json({
      success: false,
      message: "Phiên đăng nhập không hợp lệ hoặc đã hết hạn!",
    });
  }
};


const checkAdminOrOwner = async (req, res, next) => {
  const { id } = req.params;
  const userIdFromToken = req.user.id; // Lấy ID từ token đã xác thực
  const userRoleFromToken = req.user.role; // Lấy role từ token

  if (userRoleFromToken === "admin" || userIdFromToken === id) {
    return next();
  }

  return res.status(403).json({
    success: false,
    message: "Bạn không có quyền thực hiện hành động này.",
  });
};

// const authJwt = () => {
//   const secret = process.env.JWT_SECRET;

//   return (req, res, next) => {
//     const token = req.headers["authorization"]?.split(" ")[1]; // Lấy token từ header Authorization

//     if (!token) {
//       return res.status(403).json({ message: "Token không được cung cấp." });
//     }

//     // Xác thực và giải mã token
//     jwt.verify(token, secret, { algorithms: ["HS256"] }, (err, decoded) => {
//       if (err) {
//         return res.status(401).json({ message: "Token không hợp lệ." });
//       }

//       req.user = decoded; // Lưu thông tin người dùng đã giải mã vào request
//       next(); // Tiến hành với các middleware hoặc route tiếp theo
//     });
//   };
// };

// const isAdmin = (req, res, next) => {
//   try {
//     // Lấy token từ header
//     const token = req.headers.authorization?.split(" ")[1];
//     if (!token) {
//       return res.status(401).json({
//         success: false,
//         message: "Không có token xác thực.",
//       });
//     }

//     // Giải mã token để lấy thông tin người dùng
//     const decoded = jwt.verify(token, process.env.JWT_SECRET);

//     // Kiểm tra vai trò (role) của người dùng
//     if (decoded.role !== "admin") {
//       return res.status(403).json({
//         success: false,
//         message: "Bạn không có quyền truy cập.",
//       });
//     }

//     // Gắn thông tin user vào request để sử dụng sau này
//     req.user = decoded;
//     next();
//   } catch (error) {
//     return res.status(401).json({
//       success: false,
//       message: "Token không hợp lệ hoặc đã hết hạn.",
//     });
//   }
// };


const authJwt = () => {
  const secret = process.env.JWT_SECRET;

  return (req, res, next) => {
    // ✨ Lấy token từ Cookie hoặc Header
    const token = req.cookies.token || req.headers["authorization"]?.split(" ")[1];

    if (!token) {
      return res.status(401).json({ message: "Token không được cung cấp." });
    }

    // Xác thực và giải mã token
    jwt.verify(token, secret, { algorithms: ["HS256"] }, (err, decoded) => {
      if (err) {
        return res.status(401).json({ message: "Token không hợp lệ hoặc đã hết hạn." });
      }

      req.user = decoded;
      next();
    });
  };
};

const isAdmin = (req, res, next) => {
  try {
    // ✨ Lấy token từ Cookie hoặc Header
    const token = req.cookies.token || req.headers.authorization?.split(" ")[1];
    
    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Không có token xác thực.",
      });
    }

    // Giải mã token để lấy thông tin người dùng
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Kiểm tra vai trò (role) của người dùng
    if (decoded.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Bạn không có quyền truy cập.",
      });
    }

    // Gắn thông tin user vào request
    req.user = decoded;
    next();
  } catch (error) {
    // Xử lý lỗi giải mã token
    return res.status(401).json({
      success: false,
      message: "Token không hợp lệ hoặc đã hết hạn.",
    });
  }
};

module.exports = {
  hashPassword,
  checkPassword,
  isValidPhone,
  verifyToken,
  generateToken,
  handleError,
  isValidEmail,
  isValidPassword,
  checkAdminOrOwner,
  authJwt,
  isAdmin,
};
