// helpers/password.js
const bcrypt = require("bcryptjs");

// Mã hóa mật khẩu
exports.hashPassword = async (password) => {
  const salt = await bcrypt.genSalt(10);
  return await bcrypt.hash(password, salt);
};

// Kiểm tra mật khẩu
exports.checkPassword = async (password, hashedPassword) => {
  return await bcrypt.compare(password, hashedPassword);
};
