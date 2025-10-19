const mongoose = require("mongoose");

const OrderSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    items: [
      {
        productId: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "Product",
          required: true,
        },
        quantity: {
          type: Number,
          required: true,
        },
        price: {
          type: Number,
          required: true,
        },
        color: String,
        size: String,

        images: [String],
      },
    ],
    isVouched: [
      {
        isVoucher: {
          type: Boolean,
          default: false, // Đặt giá trị mặc định là false cho thuộc tính isVoucher
        },
        voucherCode: {
          type: String,
        },
        discountPercentage: {
          type: Number,
        },
        appliedDate: {
          type: String,
        },
      },
    ],

    totalPrice: {
      type: Number,
      required: true,
    },
    address: {
      province: String,
      provinceCode: String,
      district: String,
      districtCode: String,
      ward: String,
      wardCode: String,
      phone: String,
      detail: String,
      notes: String,
    },
    paymentMethod: {
      type: String,
      required: true,
    },
    orderDate: {
      type: Date,
      default: Date.now,
    },
    status: {
      type: String,
      enum: ["Pending", "Packed", "In Transit", "Completed", "Cancelled"],
      default: "Pending",
    },
  },
  { timestamps: true }
);

// Tạo virtual cho thuộc tính id
OrderSchema.virtual("id").get(function () {
  return this._id.toHexString();
});

// Cấu hình JSON để bao gồm các thuộc tính ảo (virtuals)
OrderSchema.set("toJSON", {
  virtuals: true,
});

// Xuất cả CategoryModel và OrderSchema
module.exports = {
  OrderModel: mongoose.model("Order", OrderSchema),
  OrderSchema: OrderSchema,
};
