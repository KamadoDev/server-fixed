const mongoose = require("mongoose");

const ReviewSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId, // Liên kết với bảng User
      ref: "User",
      required: true,
    },
    productId: {
      type: mongoose.Schema.Types.ObjectId, // Liên kết với bảng Product
      ref: "Product",
      required: true,
    },
    rating: {
      type: Number,
      required: true,
      min: 1, // Điểm đánh giá tối thiểu là 1
      max: 5, // Điểm đánh giá tối đa là 5
    },
    reviewText: {
      type: String,
      required: false,
      maxlength: 1000, // Giới hạn độ dài tối đa cho nội dung đánh giá
    },
    createdAt: {
      type: Date,
      default: Date.now,
    },
    updatedAt: {
      type: Date,
      default: Date.now,
    },
  },
  { timestamps: true } // Tự động tạo trường createdAt và updatedAt
);

// Tạo chỉ mục để tối ưu tìm kiếm theo userId và productId
ReviewSchema.index({ userId: 1 });
ReviewSchema.index({ productId: 1 });

// Tạo virtual cho thuộc tính id
ReviewSchema.virtual("id").get(function () {
  return this._id.toHexString();
});

// Cấu hình JSON để bao gồm các thuộc tính ảo (virtuals)
ReviewSchema.set("toJSON", {
  virtuals: true,
});

// Xuất cả CategoryModel và ReviewSchema
module.exports = {
  ReviewModel: mongoose.model("Review", ReviewSchema),
  ReviewSchema: ReviewSchema,
};
