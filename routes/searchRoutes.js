const express = require("express");
const { ProductModel } = require("../models/ProductModel");
const router = express.Router();

router.get("/", async (req, res) => {
  try {
    const query = req.query.q ? req.query.q.trim() : ''; // Lấy và làm sạch query
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 8;

    // 1. XÁC THỰC VÀ NGĂN CHẶN CÁC TRUY VẤN KHÔNG HỢP LỆ (BẢO MẬT & HIỆU SUẤT)
    // 1.1. Kiểm tra query rỗng hoặc quá ngắn
    if (!query || query.length < 2) {
      return res.status(400).json({
        success: false,
        message: "Vui lòng cung cấp truy vấn tìm kiếm hợp lệ (tối thiểu 2 ký tự).",
        type: "error",
      });
    }

    // 1.2. LÀM SẠCH KÝ TỰ REGEX ĐẶC BIỆT
    // Ngăn chặn việc người dùng inject các ký tự regex đặc biệt để khớp với mọi thứ (như .*)
    const specialCharsRegex = /[.*+?^${}()|[\]\\]/g;
    
    // Nếu truy vấn chỉ chứa các ký tự đặc biệt hoặc các ký tự wildcard như '.*', từ chối.
    // Kiểm tra để đảm bảo truy vấn KHÔNG chỉ là các ký tự đặc biệt/wildcard (sau khi loại bỏ khoảng trắng)
    const isOnlyWildcard = (query) => {
        const cleanedQuery = query.replace(/\s/g, ''); // Loại bỏ khoảng trắng
        return cleanedQuery.match(/^[.*+?^${}()|[\]\\]+$/) !== null;
    };

    if (isOnlyWildcard(query)) {
        return res.status(400).json({
            success: false,
            message: "Truy vấn tìm kiếm không được chứa chỉ các ký tự đặc biệt.",
            type: "error",
        });
    }

    // Escape (thoát) các ký tự đặc biệt trong chuỗi để chúng được coi là ký tự văn bản thông thường
    const safeQuery = query.replace(specialCharsRegex, '\\$&');

    // 2. TẠO TRUY VẤN MONGODB AN TOÀN
    const searchCondition = {
      name: { $regex: safeQuery, $options: "i" }, // Sử dụng safeQuery
    };

    // Tìm sản phẩm theo tên (case-insensitive)
    const items = await ProductModel.find(searchCondition)
      .skip((page - 1) * limit)
      .limit(limit);

    // Tính tổng số sản phẩm
    const totalItems = await ProductModel.countDocuments(searchCondition);

    const totalPages = Math.ceil(totalItems / limit);

    // Trả kết quả tìm kiếm và phân trang
    res.json({
      success: true,
      message: "Search results",
      items,
      totalItems,
      totalPages,
      currentPage: page,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      success: false,
      message: `An error occurred while searching for products: ${error.message}`,
      type: "error",
    });
  }
});

module.exports = router;