const mongoose = require("mongoose");

const favoriteProductSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId, // Liên kết với bảng User
      ref: "User",
      required: true,
    },
    products: [
      {
        productId: {
          type: mongoose.Schema.Types.ObjectId, // Liên kết với bảng Product
          ref: "Product",
          required: true,
        },
        addedAt: {
          type: Date,
          default: Date.now,
        },
      },
    ],
  },
  { timestamps: true }
);

// Tạo chỉ mục cho userId và productId để tối ưu tìm kiếm
favoriteProductSchema.index({ userId: 1 }); // Tạo chỉ mục cho userId
favoriteProductSchema.index({ "products.productId": 1 }); // Tạo chỉ mục cho productId trong mảng products

// Tạo virtual cho thuộc tính id
favoriteProductSchema.virtual("id").get(function () {
  return this._id.toHexString();
});

// Cấu hình JSON để bao gồm các thuộc tính ảo (virtuals)
favoriteProductSchema.set("toJSON", {
  virtuals: true,
});

// Xuất cả CategoryModel và favoriteProductSchema
module.exports = {
  FavoriteProductModel: mongoose.model(
    "FavoriteProduct",
    favoriteProductSchema
  ),
  favoriteProductSchema: favoriteProductSchema,
};
