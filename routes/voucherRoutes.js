const express = require("express");
const { verifyToken, checkAdminOrOwner } = require("../helper/authHelpers");
const { VoucherModel } = require("../models/VoucherModel");
const router = express.Router();

router.get("/", async (req, res) => {
  try {
    const page = parseInt(req.query.page, 10) || 1;
    const perPage = 12;

    // Kiểm tra nếu page không phải là số hợp lệ
    if (isNaN(page) || page < 1) {
      return res.status(400).json({
        success: false,
        message: "Invalid page number",
      });
    }

    const totalVoucher = await VoucherModel.countDocuments();
    const totalPages = Math.ceil(totalVoucher / perPage);

    // Kiểm tra nếu page lớn hơn tổng số trang
    if (page > totalPages) {
      return res.status(404).json({
        success: false,
        message: "Voucher not found",
      });
    }

    // Truy vấn sản phẩm với phân trang
    const voucherList = await VoucherModel.find()
      .skip((page - 1) * perPage)
      .limit(perPage)
      .exec();

    // Kiểm tra nếu không có sản phẩm
    if (voucherList.length === 0) {
      return res.status(200).json({
        success: true,
        message: "No voucher available",
      });
    }

    // Trả về thông tin sản phẩm và phân trang
    return res.status(200).json({
      success: true,
      voucher: voucherList,
      totalPages,
      currentPage: page,
      totalItems: totalVoucher,
      perPage,
    });
  } catch (err) {
    // Xử lý lỗi nếu có
    console.error("Error fetching products:", err);
    return res.status(500).json({
      success: false,
      message: err.message || "An error occurred while fetching products",
    });
  }
});

router.post("/create", verifyToken, checkAdminOrOwner, async (req, res) => {
  const {
    code,
    discountType,
    discountValue,
    minOrderValue,
    maxDiscountValue,
    expirationDate,
    usageLimit,
  } = req.body;

  // Kiểm tra các trường bắt buộc
  const requiredFields = [
    { field: code, message: "Mã voucher không được để trống" },
    {
      field: discountType,
      message: "Loại giảm giá không được để trống",
      allowedValues: ["percentage", "fixed"],
    },
    {
      field: discountValue,
      message: "Giá trị giảm không được để trống",
      type: "number",
      min: 0,
    },
    {
      field: minOrderValue,
      message: "Giá trị đơn hàng tối thiểu không được để trống",
      type: "number",
      min: 0,
    },
    {
      field: maxDiscountValue,
      message: "Giá trị giảm tối đa phải là số và không nhỏ hơn 0",
      type: "number",
      min: 0,
      optional: true, // Cho phép bỏ trống
    },
    {
      field: expirationDate,
      message: "Ngày hết hạn không được để trống",
    },
    {
      field: usageLimit,
      message: "Số lượng sử dụng không được để trống",
      type: "number",
      min: 1,
    },
  ];

  // Duyệt qua danh sách và kiểm tra từng trường
  for (const {
    field,
    message,
    type,
    min,
    max,
    allowedValues,
    optional,
  } of requiredFields) {
    if (!field && field !== 0) {
      if (optional) continue; // Bỏ qua trường tùy chọn
      return res.status(400).json({ success: false, message, type: "error" });
    }

    // Kiểm tra kiểu dữ liệu
    if (
      type === "number" &&
      (isNaN(field) || field < min || (max !== undefined && field > max))
    ) {
      return res.status(400).json({
        success: false,
        message: `${message} và phải là số thực từ ${min}`,
        type: "error",
      });
    }

    // Kiểm tra giá trị hợp lệ
    if (allowedValues && !allowedValues.includes(field)) {
      return res.status(400).json({
        success: false,
        message: `${message}. Giá trị hợp lệ: ${allowedValues.join(", ")}`,
        type: "error",
      });
    }
  }

  try {
    // Kiểm tra nếu mã voucher đã tồn tại
    const existingVoucher = await VoucherModel.findOne({ code });
    if (existingVoucher) {
      return res.status(400).json({
        message: "Mã voucher đã tồn tại",
        status: false,
      });
    }

    // Tạo voucher mới
    const newVoucher = new VoucherModel({
      code,
      discountType,
      discountValue,
      minOrderValue,
      maxDiscountValue,
      expirationDate,
      usageLimit,
    });

    await newVoucher.save();

    res.status(201).json({
      message: "Voucher đã được tạo thành công",
      voucher: newVoucher,
      status: true,
      type: "success",
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      message: "Đã xảy ra lỗi khi tạo voucher",
      error: err.message,
      status: false,
      type: "error",
    });
  }
});

router.post("/apply", verifyToken, async (req, res) => {
  const { code, totalPrice } = req.body;

  try {
    // Tìm voucher theo mã và trạng thái
    const voucher = await VoucherModel.findOne({ code, active: true });

    if (!voucher) {
      return res.status(404).json({
        message: "Voucher không tồn tại hoặc đã hết hiệu lực",
        status: false,
      });
    }

    // Kiểm tra ngày hết hạn
    const currentDate = new Date();
    if (currentDate > new Date(voucher.expirationDate)) {
      return res.status(400).json({
        message: "Voucher đã hết hạn",
        status: false,
      });
    }

    // Kiểm tra giá trị đơn hàng tối thiểu
    if (totalPrice < voucher.minOrderValue) {
      return res.status(400).json({
        message: `Đơn hàng phải có giá trị tối thiểu là ${voucher.minOrderValue}`,
        status: false,
      });
    }

    // Kiểm tra số lần sử dụng
    if (voucher.usageLimit > 0 && voucher.usedCount >= voucher.usageLimit) {
      return res.status(400).json({
        message: "Voucher đã đạt đến giới hạn sử dụng",
        status: false,
      });
    }

    // Tính giảm giá
    let discount = 0;
    if (voucher.discountType === "percentage") {
      discount = (totalPrice * voucher.discountValue) / 100;
      if (voucher.maxDiscountValue) {
        discount = Math.min(discount, voucher.maxDiscountValue);
      }
    } else if (voucher.discountType === "fixed") {
      discount = Math.min(voucher.discountValue, totalPrice);
    }

    // Cập nhật số lần sử dụng
    voucher.usedCount += 1;
    await voucher.save();

    // Trả kết quả
    res.status(200).json({
      message: "Voucher đã được áp dụng thành công",
      discount: discount.toFixed(2), // Định dạng giá trị giảm giá (2 chữ số thập phân)
      finalPrice: (totalPrice - discount).toFixed(2),
      usageLimit: voucher.usageLimit,
      usedCount: voucher.usedCount,
      voucherCode: voucher.code,
      applyDate: new Date().toLocaleString("vi-VN", {
        year: "numeric",
        month: "long",
        day: "numeric",
        hour: "numeric",
        minute: "numeric",
      }), // Thêm ngày áp dụng
      status: true,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      message: "Đã xảy ra lỗi khi áp dụng voucher",
      error: err.message,
      status: false,
    });
  }
});

// Xóa một voucher
router.delete(
  "/delete/:id",
  verifyToken,
  checkAdminOrOwner,
  async (req, res) => {
    const { id } = req.params;

    try {
      // Kiểm tra voucher có tồn tại
      const voucher = await VoucherModel.findById(id);
      if (!voucher) {
        return res.status(404).json({
          success: false,
          message: "Voucher không tồn tại",
          type: "error",
        });
      }

      // Xóa voucher
      await VoucherModel.findByIdAndDelete(id);

      return res.status(200).json({
        success: true,
        message: "Voucher đã được xóa thành công",
        type: "success",
      });
    } catch (err) {
      console.error("Error deleting voucher:", err.message);
      return res.status(500).json({
        success: false,
        message: "Đã xảy ra lỗi khi xóa voucher",
        error: err.message,
        type: "error",
      });
    }
  }
);

module.exports = router;
