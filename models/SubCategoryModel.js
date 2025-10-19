const mongoose = require("mongoose");

const SubCategorySchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  parentCategory: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Category",
    required: true,
  },
});

// Tạo virtual cho thuộc tính id
SubCategorySchema.virtual("id").get(function () {
  return this._id.toHexString();
});

// Cấu hình JSON để bao gồm các thuộc tính ảo (virtuals)
SubCategorySchema.set("toJSON", {
  virtuals: true,
});

module.exports = {
  SubCategoryModel: mongoose.model("SubCategory", SubCategorySchema),
  SubCategorySchema: SubCategorySchema,
};
