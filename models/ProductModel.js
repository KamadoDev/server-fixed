const mongoose = require("mongoose");

const ProductSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, required: true },
  price: { type: Number, required: true, default: 0 },
  old_price: { type: Number, default: 0 },
  discount: { type: Number, default: 0 },
  brand: { type: String, required: true },
  category: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Category",
    required: true,
  },
  sub_category: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "SubCategory",
    required: true,
  },
  images: [
    {
      url: { type: String, required: true },
      public_id: { type: String, required: true },
    },
  ],
  productInStock: { type: Number, required: true },
  isFeatured: { type: Boolean, default: false },
  size: [{ type: String, required: true }],
  colors: [{ type: String, required: true }],
  tags: [{ type: String }],

  numberReviews: { type: Number, default: 0 },
  rating: { type: Number, default: 0 },

  createdAt: { type: Date, default: Date.now, required: true },
  updatedAt: { type: Date },
});

// Tạo virtual cho thuộc tính id
ProductSchema.virtual("id").get(function () {
  return this._id.toHexString();
});

// Cấu hình JSON để bao gồm các thuộc tính ảo (virtuals)
ProductSchema.set("toJSON", {
  virtuals: true,
});

// Xuất cả ProductModel và ProductSchema
module.exports = {
  ProductModel: mongoose.model("Product", ProductSchema),
  ProductSchema: ProductSchema,
};
