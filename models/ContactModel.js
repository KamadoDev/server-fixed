const mongoose = require("mongoose");

const ContactSchema = new mongoose.Schema(
  {
    emailOrPhone: {
      type: String,
      required: true,
      trim: true,
    },
    message: {
      type: String,
      required: true,
      trim: true,
    },
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User", // Đảm bảo trường này liên kết với model "User"
      required: true,
    },
  },
  { timestamps: true } // Tự động thêm các trường createdAt và updatedAt
);

// Tạo virtual cho thuộc tính id
ContactSchema.virtual("id").get(function () {
  return this._id.toHexString();
});

// Cấu hình JSON để bao gồm các thuộc tính ảo (virtuals)
ContactSchema.set("toJSON", {
  virtuals: true,
});

// Xuất cả ContactModel và ContactSchema
module.exports = {
  ContactModel: mongoose.model("Contact", ContactSchema),
  ContactSchema: ContactSchema,
};
