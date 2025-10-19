const express = require("express");
const { verifyToken, checkAdminOrOwner } = require("../helper/authHelpers");
const { ReviewModel } = require("../models/ReviewModel");
const { UserModel } = require("../models/UserModel");
const router = express.Router();

router.get("/:productId", async (req, res) => {
  const { productId } = req.params;

  try {
    const reviews = await ReviewModel.find({ productId })
      .populate("userId", "fullName") // Lấy trường "name" từ User
      .sort({ createdAt: -1 }); // Sắp xếp đánh giá theo thời gian (mới nhất trước)

    if (!reviews.length) {
      return res.status(404).json({
        status: false,
        message: "Không tìm thấy đánh giá nào cho sản phẩm này",
      });
    }

    res.status(200).json({
      status: true,
      message: "Lấy danh sách đánh giá thành công",
      reviews,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      status: false,
      message: "Có lỗi xảy ra khi lấy danh sách đánh giá",
      error: error.message,
    });
  }
});

router.get(":productId/review/:userId", verifyToken, async (req, res) => {
  const { productId, userId } = req.params;

  try {
    const review = await ReviewModel.findOne({ productId, userId });

    if (!review) {
      return res.status(404).json({
        success: false,
        message: "Người dùng chưa đánh giá sản phẩm này",
      });
    }

    res.status(200).json({
      success: true,
      message: "Lấy đánh giá thành công",
      review,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      success: false,
      message: "Có lỗi xảy ra khi lấy đánh giá",
      error: error.message,
    });
  }
});

router.post("/newReview/:userId", verifyToken, async (req, res) => {
  const { userId } = req.params;
  const { productId, rating, reviewText } = req.body;

  // Tìm người dùng theo ID
  const user = await UserModel.findById(userId).select("-password");

  // Kiểm tra nếu không tìm thấy user
  if (!user) {
    return res.status(404).json({
      success: false,
      message: "Vui lòng đăng nhập.",
      type: "error",
    });
  }

  if (!productId || !rating) {
    return res.status(400).json({
      success: false,
      message: "Thiếu dữ liệu bắt buộc",
      type: "error",
    });
  }

  try {
    const newReview = new ReviewModel({
      userId,
      productId,
      rating,
      reviewText,
    });

    await newReview.save();

    res.status(201).json({
      success: true,
      message: "Đã ghi nhận đánh giá của bạn!",
      review: newReview,
      type: "success",
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      success: false,
      message: "Có lỗi xảy ra khi tạo đánh giá",
      error: error.message,
      type: "error",
    });
  }
});

router.put("/updateReview/:id", verifyToken, async (req, res) => {
  const { id } = req.params;
  const { rating, reviewText } = req.body;

  try {
    const updatedReview = await ReviewModel.findByIdAndUpdate(
      id,
      { rating, reviewText, updatedAt: Date.now() },
      { new: true } // Trả về document đã được cập nhật
    );

    if (!updatedReview) {
      return res.status(404).json({
        success: false,
        message: "Không tìm thấy đánh giá",
      });
    }

    res.status(200).json({
      success: true,
      message: "Đánh giá đã được cập nhật thành công",
      review: updatedReview,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      success: false,
      message: "Có lỗi xảy ra khi cập nhật đánh giá",
      error: error.message,
    });
  }
});

router.delete("/deleteReview/:userId/:id", verifyToken, async (req, res) => {
  const { userId, id } = req.params;

  try {
    // Tìm review với id
    const reviewToDelete = await ReviewModel.findById(id);

    if (!reviewToDelete) {
      return res.status(404).json({
        success: false,
        message: "Không tìm thấy đánh giá",
        type: "error",
      });
    }

    // Kiểm tra userId có khớp không
    if (reviewToDelete.userId.toString() !== userId) {
      return res.status(403).json({
        success: false,
        message: "Bạn không có quyền xóa đánh giá này",
        type: "error",
      });
    }

    // Xóa review nếu userId khớp
    await ReviewModel.findByIdAndDelete(id);

    res.status(200).json({
      success: true,
      message: "Đánh giá đã được xóa thành công",
      type: "success",
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      success: false,
      message: "Có lỗi xảy ra khi xóa đánh giá",
      error: error.message,
      type: "error",
    });
  }
});

router.get(
  "/getAverageRating/:productId",
  verifyToken,
  checkAdminOrOwner,
  async (req, res) => {
    const { productId } = req.params;

    try {
      const ratings = await ReviewModel.aggregate([
        { $match: { productId: mongoose.Types.ObjectId(productId) } },
        { $group: { _id: "$productId", averageRating: { $avg: "$rating" } } },
      ]);

      if (ratings.length === 0) {
        return res.status(404).json({
          success: false,
          message: "Không có đánh giá nào cho sản phẩm này",
        });
      }

      res.status(200).json({
        success: true,
        message: "Tính điểm trung bình thành công",
        averageRating: ratings[0].averageRating,
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({
        success: false,
        message: "Có lỗi xảy ra khi tính điểm trung bình",
        error: error.message,
      });
    }
  }
);

module.exports = router;
