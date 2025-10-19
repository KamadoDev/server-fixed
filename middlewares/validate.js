const Joi = require("joi");

// ✅ Validate đăng ký
exports.validateSignup = (req, res, next) => {
  const schema = Joi.object({
    username: Joi.string().trim().alphanum().min(3).max(30).required(),
    phone: Joi.string().pattern(/^(0|\+?\d{1,3})[0-9]{9,14}$/).required(),
    fullName: Joi.string().trim().min(3).max(100).required(),
    password: Joi.string()
      .min(8)
      .max(64)
      .pattern(/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d).+$/)
      .message("Mật khẩu phải có ít nhất 1 chữ hoa, 1 chữ thường và 1 số")
      .required(),
    confirmPassword: Joi.any()
      .valid(Joi.ref("password"))
      .required()
      .messages({ "any.only": "Mật khẩu xác nhận không khớp" }),
  });

  const { error } = schema.validate(req.body, { abortEarly: false, stripUnknown: true });
  if (error) {
    return res.status(400).json({
      success: false,
      message: "Dữ liệu đăng ký không hợp lệ",
      details: error.details.map((d) => d.message),
    });
  }

  next();
};

// ✅ Validate đăng nhập
exports.validateSignin = (req, res, next) => {
  const schema = Joi.object({
    usernameOrPhone: Joi.alternatives()
      .try(
        Joi.string().trim().alphanum().min(3).max(30),
        Joi.string().pattern(/^(0|\+?\d{1,3})[0-9]{9,14}$/)
      )
      .required(),
    password: Joi.string().min(6).max(64).required(),
  });

  const { error } = schema.validate(req.body, { abortEarly: false, stripUnknown: true });
  if (error) {
    return res.status(400).json({
      success: false,
      message: "Dữ liệu đăng nhập không hợp lệ",
      details: error.details.map((d) => d.message),
    });
  }

  next();
};

// ✅ Validate tạo đơn hàng
exports.validateOrder = (req, res, next) => {
  const schema = Joi.object({
    userId: Joi.string().regex(/^[a-f\d]{24}$/i).required(), // ID MongoDB
    fullName: Joi.string().trim().min(3).max(100).required(),
    phone: Joi.string().pattern(/^(0|\+?\d{1,3})[0-9]{9,14}$/).required(),
    province: Joi.string().trim().required(),
    district: Joi.string().trim().required(),
    ward: Joi.string().trim().required(),
    detail: Joi.string().trim().min(3).required(),
    paymentMethod: Joi.string().valid("COD", "Online").required(),
    totalPrice: Joi.number().positive().min(0).required(),
    items: Joi.array()
      .items(
        Joi.object({
          productId: Joi.string().regex(/^[a-f\d]{24}$/i).required(),
          quantity: Joi.number().integer().min(1).required(),
          price: Joi.number().min(0).required(),
        })
      )
      .min(1)
      .required(),
  });

  const { error } = schema.validate(req.body, { abortEarly: false, stripUnknown: true });
  if (error) {
    return res.status(400).json({
      success: false,
      message: "Dữ liệu đơn hàng không hợp lệ",
      details: error.details.map((d) => d.message),
    });
  }

  next();
};
