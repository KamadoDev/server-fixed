const express = require("express");
const { verifyToken } = require("../helper/authHelpers");
const { FavoriteProductModel } = require("../models/FavoriteProductModel");
const router = express.Router();

router.get("/:userId", verifyToken, async (req, res) => {
  const { userId } = req.params;
  try {
    const favorite = await FavoriteProductModel.findOne({ userId }).populate(
      "products.productId"
    );

    if (!favorite) {
      return res.status(404).json({
        status: false,
        message: "Danh sách yêu thích không tồn tại",
        type: "error",
      });
    }

    res.status(200).json({
      status: true,
      message: "Lấy danh sách sản phẩm yêu thích thành công",
      data: favorite,
      type: "success",
    });
  } catch (error) {
    res.status(500).json({
      message: "Lỗi khi lấy danh sách sản phẩm yêu thích",
      error: error.message,
      status: false,
      type: "error",
    });
  }
});

router.post("/add", verifyToken, async (req, res) => {
  const { userId, productId } = req.body;

  try {
    // Kiểm tra xem người dùng đã có danh sách yêu thích chưa
    let favorite = await FavoriteProductModel.findOne({ userId });

    // Nếu chưa có, tạo mới danh sách yêu thích
    if (!favorite) {
      favorite = new FavoriteProductModel({
        userId,
        products: [{ productId }],
      });
    } else {
      // Nếu đã có, thêm sản phẩm vào danh sách yêu thích
      const existingProduct = favorite.products.some(
        (item) => item.productId.toString() === productId.toString()
      );

      if (existingProduct) {
        return res.status(400).json({
          message: "Sản phẩm đã có trong danh sách yêu thích",
          status: false,
          type: "error",
        });
      }

      favorite.products.push({ productId });
    }

    // Lưu hoặc cập nhật danh sách yêu thích
    await favorite.save();

    res.status(201).json({
      message: "Đã thêm sản phẩm vào danh sách yêu thích",
      status: true,
      type: "success",
      data: favorite,
    });
  } catch (error) {
    res.status(500).json({
      message: "Lỗi khi thêm sản phẩm yêu thích",
      error: error.message,
      status: false,
      type: "error",
    });
  }
});

router.delete("/delete/:userId", verifyToken, async (req, res) => {
  const { userId } = req.params;
  const { productId } = req.body;

  try {
    const favorite = await FavoriteProductModel.findOne({ userId });

    if (!favorite) {
      return res.status(404).json({
        message: "Danh sách yêu thích không tồn tại",
        status: false,
        type: "error",
      });
    }

    // Kiểm tra nếu sản phẩm có trong danh sách yêu thích
    const productIndex = favorite.products.findIndex(
      (item) => item.productId.toString() === productId.toString()
    );

    if (productIndex === -1) {
      return res.status(404).json({
        message: "Sản phẩm không có trong danh sách yêu thích",
        status: false,
        type: "error",
      });
    }

    // Xóa sản phẩm khỏi danh sách yêu thích
    favorite.products.splice(productIndex, 1);

    await favorite.save();

    res.status(200).json({
      message: "Đã xóa sản phẩm khỏi danh sách yêu thích",
      status: true,
      type: "success",
      data: favorite,
    });
  } catch (error) {
    res.status(500).json({
      message: "Lỗi khi xóa sản phẩm yêu thích",
      error: error.message,
      status: false,
      type: "error",
    });
  }
});

module.exports = router;
