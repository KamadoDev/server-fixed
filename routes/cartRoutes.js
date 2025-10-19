const express = require("express");
const router = express.Router();
const { ProductModel } = require("../models/ProductModel");
const { verifyToken } = require("../helper/authHelpers");
const { CartModel } = require("../models/CartModel");

// api/getCart
router.get("/getCart/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const cart = await CartModel.findOne({ userId: id }).populate(
      "items.productId"
    );

    if (!cart) {
      return res.status(404).json({ message: "Giỏ hàng không tồn tại" });
    }

    res.status(200).json(cart);
  } catch (err) {
    console.error(err);
    res
      .status(500)
      .json({ message: "Đã xảy ra lỗi khi lấy giỏ hàng", error: err.message });
  }
});

// api/addCart
router.post("/addCart", verifyToken, async (req, res) => {
  const { userId, productId, quantity, size, color } = req.body;

  if (!size || !color) {
    return res.status(400).json({
      status: false,
      message: "Size và màu sản phẩm là bắt buộc",
      type: "error",
    });
  }

  try {
    const product = await ProductModel.findById(productId);

    if (!product) {
      return res.status(404).json({
        status: false,
        type: "error",
        message: "Sản phẩm không tồn tại",
      });
    }

    const discountedPrice =
      product.discount > 0
        ? product.price - (product.price * product.discount) / 100
        : product.price;

    let cart = await CartModel.findOne({ userId });

    if (!cart) {
      cart = new CartModel({
        userId,
        items: [],
        totalPrice: 0,
      });
    }

    const itemIndex = cart.items.findIndex(
      (item) =>
        item.productId.toString() === productId &&
        item.size === size &&
        item.color === color
    );

    if (itemIndex > -1) {
      cart.items[itemIndex].quantity += quantity;
      cart.items[itemIndex].price =
        cart.items[itemIndex].quantity * discountedPrice;
    } else {
      cart.items.push({
        productId,
        quantity,
        price: discountedPrice * quantity,
        size,
        color,
        images: product.images[0].url,
      });
    }

    cart.totalPrice = cart.items.reduce((total, item) => total + item.price, 0);

    await cart.save();

    res.status(200).json({
      message: "Sản phẩm đã được thêm vào giỏ hàng",
      status: true,
      cart,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      message: "Đã xảy ra lỗi khi thêm sản phẩm vào giỏ hàng",
      error: err.message,
      status: false,
    });
  }
});

router.put("/updateCart", verifyToken, async (req, res) => {
  const { userId, productId, quantity, size, color } = req.body;

  if (!size || !color || !quantity) {
    return res.status(400).json({
      status: false,
      message: "Size, màu sản phẩm và số lượng là bắt buộc",
      type: "error",
    });
  }

  try {
    const product = await ProductModel.findById(productId);

    if (!product) {
      return res.status(404).json({
        status: false,
        type: "error",
        message: "Sản phẩm không tồn tại",
      });
    }

    const discountedPrice =
      product.discount > 0
        ? product.price - (product.price * product.discount) / 100
        : product.price;

    let cart = await CartModel.findOne({ userId });

    if (!cart) {
      return res.status(404).json({
        status: false,
        message: "Giỏ hàng không tồn tại",
        type: "error",
      });
    }

    const itemIndex = cart.items.findIndex(
      (item) =>
        item.productId.toString() === productId &&
        item.size === size &&
        item.color === color
    );

    if (itemIndex === -1) {
      return res.status(404).json({
        status: false,
        message: "Sản phẩm không có trong giỏ hàng",
        type: "error",
      });
    }

    cart.items[itemIndex].quantity = quantity;
    cart.items[itemIndex].price = quantity * discountedPrice;

    cart.totalPrice = cart.items.reduce((total, item) => total + item.price, 0);

    await cart.save();

    res.status(200).json({
      message: "Giỏ hàng đã được cập nhật",
      status: true,
      cart,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      message: "Đã xảy ra lỗi khi cập nhật giỏ hàng",
      error: err.message,
      status: false,
    });
  }
});

// api/removeCart
router.delete("/removeCart/:id", verifyToken, async (req, res) => {
  const { id } = req.params;
  const { productId } = req.body; // productId cần xóa

  try {
    // Tìm giỏ hàng của người dùng
    const cart = await CartModel.findOne({ userId: id });

    if (!cart) {
      return res.status(404).json({
        status: false,
        type: "error",
        message: "Giỏ hàng không tồn tại",
      });
    }

    // Kiểm tra nếu sản phẩm có trong giỏ hàng không
    const itemIndex = cart.items.findIndex(
      (item) => item.productId.toString() === productId
    );

    if (itemIndex === -1) {
      return res.status(404).json({
        status: false,
        type: "error",
        message: "Sản phẩm không có trong giỏ hàng",
      });
    }

    // Xóa sản phẩm khỏi giỏ hàng
    cart.items.splice(itemIndex, 1);

    // Cập nhật tổng giá trị giỏ hàng
    cart.totalPrice = cart.items.reduce((total, item) => total + item.price, 0);

    // Lưu giỏ hàng sau khi xóa sản phẩm
    await cart.save();

    res.status(200).json({
      status: true,
      type: "success",
      message: "Xóa sản này trong giỏ hành thành công",
      cart,
    }); // Trả về giỏ hàng đã được cập nhật
  } catch (err) {
    console.error(err);
    res
      .status(500)
      .json({ message: "Đã xảy ra lỗi khi xóa sản phẩm khỏi giỏ hàng" });
  }
});

module.exports = router;
