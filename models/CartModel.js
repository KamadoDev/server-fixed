const mongoose = require("mongoose");

const CartSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true, // Liên kết với người dùng
    },
    items: [
      {
        productId: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "Product",
          required: true, // Liên kết với sản phẩm
        },
        quantity: {
          type: Number,
          required: true,
          min: [1, "Số lượng không được nhỏ hơn 1"],
          default: 1, // Số lượng mặc định
        },
        price: {
          type: Number,
          required: true, // Giá sản phẩm tại thời điểm thêm vào giỏ
        },
        color: {
          type: String,
          required: true, // Màu sản phẩm
        },
        size: {
          type: String,
          required: true, // Kích thước sản phẩm
        },
        images: [
          {
            type: String,
            required: true, // Hình ảnh sản phẩm
          },
        ],
      },
    ],
    totalPrice: {
      type: Number,
      required: true,
      default: 0, // Tổng giá trị giỏ hàng
    },
  },
  { timestamps: true }
);

// Tạo virtual cho thuộc tính id
CartSchema.virtual("id").get(function () {
  return this._id.toHexString();
});

// Cấu hình JSON để bao gồm các thuộc tính ảo (virtuals)
CartSchema.set("toJSON", {
  virtuals: true,
});

// Xuất cả CategoryModel và CartSchema
module.exports = {
  CartModel: mongoose.model("Cart", CartSchema),
  CartSchema: CartSchema,
};
