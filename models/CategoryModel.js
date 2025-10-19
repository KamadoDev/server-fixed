const mongoose = require("mongoose");

const CategorySchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  images: [
    {
      url: {
        type: String,
        required: true,
      },
      public_id: {
        type: String,
        required: true,
      },
    },
  ],
  color: {
    type: String,
    required: true,
  },
  type: {
    type: String,
    required: true,
  },
});

// Tạo virtual cho thuộc tính id
CategorySchema.virtual("id").get(function () {
  return this._id.toHexString();
});

// Cấu hình JSON để bao gồm các thuộc tính ảo (virtuals)
CategorySchema.set("toJSON", {
  virtuals: true,
});

// Xuất cả CategoryModel và CategorySchema
module.exports = {
  CategoryModel: mongoose.model("Category", CategorySchema),
  CategorySchema: CategorySchema,
};
