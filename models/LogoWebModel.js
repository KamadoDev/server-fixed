const mongoose = require("mongoose");

const LogoWebSchema = new mongoose.Schema({
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

  type: {
    type: String,
    required: true,
  },
});

// Tạo virtual cho thuộc tính id
LogoWebSchema.virtual("id").get(function () {
  return this._id.toHexString();
});

// Cấu hình JSON để bao gồm các thuộc tính ảo (virtuals)
LogoWebSchema.set("toJSON", {
  virtuals: true,
});

// Xuất cả CategoryModel và LogoWebSchema
module.exports = {
  LogoWebModel: mongoose.model("LogoWeb", LogoWebSchema),
  LogoWebSchema: LogoWebSchema,
};
