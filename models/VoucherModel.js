const mongoose = require("mongoose");

const VoucherSchema = new mongoose.Schema(
  {
    code: {
      type: String,
      required: true,
      unique: true,
    },
    discountType: {
      type: String, // "percentage" hoặc "fixed"
      enum: ["percentage", "fixed"],
      required: true,
    },
    discountValue: {
      type: Number, // Giá trị giảm (phần trăm hoặc số tiền cố định)
      required: true,
    },
    minOrderValue: {
      type: Number, // Giá trị đơn hàng tối thiểu để áp dụng voucher
      default: 0,
    },
    maxDiscountValue: {
      type: Number, // Giá trị giảm tối đa nếu dùng percentage
      default: null,
    },
    expirationDate: {
      type: Date, // Ngày hết hạn
      required: true,
    },
    usageLimit: {
      type: Number, // Số lần sử dụng tối đa
      default: 1,
    },
    usedCount: {
      type: Number, // Số lần đã sử dụng
      default: 0,
    },
    active: {
      type: Boolean,
      default: true,
    },
  },
  { timestamps: true }
);

// Tạo virtual cho thuộc tính id
VoucherSchema.virtual("id").get(function () {
  return this._id.toHexString();
});

// Cấu hình JSON để bao gồm các thuộc tính ảo (virtuals)
VoucherSchema.set("toJSON", {
  virtuals: true,
});

// Xuất cả CategoryModel và VoucherSchema
module.exports = {
  VoucherModel: mongoose.model("Voucher", VoucherSchema),
  VoucherSchema: VoucherSchema,
};
