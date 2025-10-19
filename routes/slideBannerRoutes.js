const express = require("express");
const router = express.Router();
const cloudinary = require("../cloudinaryConfig");
const upload = require("../middlewares/multer");
const fs = require("fs"); // folder uploads
const { SlideBannerModel } = require("../models/SlideBannerModel");
const { verifyToken, checkAdminOrOwner } = require("../helper/authHelpers");
const pLimit = require("p-limit");

// lấy tất cả slide
// Get all slides, sorted by position
router.get("/", async (req, res) => {
  try {
    const slides = await SlideBannerModel.find().sort({ position: 1 }); // Sorting by position
    res.status(200).json({
      success: true,
      data: slides,
      message: "Lấy tất cả slide thành công!",
    });
  } catch (error) {
    console.error("Lỗi khi lấy slide:", error);
    res.status(500).json({
      success: false,
      message: "Không thể lấy slide!",
      error: error.message,
    });
  }
});

// API DELETE slide
router.delete("/:id", verifyToken, checkAdminOrOwner, async (req, res) => {
  try {
    // Tìm slide theo ID
    const slide = await SlideBannerModel.findById(req.params.id);

    if (!slide) {
      return res.status(404).json({
        success: false,
        message: "Không tìm thấy slide!",
        type: "error",
      });
    }

    // Xóa ảnh khỏi Cloudinary nếu có
    for (const image of slide.images) {
      await cloudinary.uploader.destroy(image.public_id);
    }

    // Sử dụng deleteOne thay vì remove()
    await SlideBannerModel.deleteOne({ _id: req.params.id });

    res.status(200).json({
      success: true,
      message: "Xóa slide thành công!",
      type: "success",
    });
  } catch (error) {
    console.error("Lỗi:", error);
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

router.post(
  "/create",
  verifyToken,
  checkAdminOrOwner,
  upload.single("images"), // Using upload.single as you are uploading one image
  async (req, res) => {
    try {
      // Check if the file is uploaded
      if (!req.file) {
        return res.status(400).json({
          success: false,
          message: "Bạn phải tải lên ít nhất 1 ảnh!",
          type: "error",
        });
      }

      // Validate the file extension
      const fileExtension = req.file.originalname
        .split(".")
        .pop()
        .toLowerCase();
      if (!["jpeg", "jpg", "png", "gif"].includes(fileExtension)) {
        return res.status(400).json({
          success: false,
          message: `Ảnh ${req.file.originalname} không hợp lệ. Chỉ chấp nhận JPEG, JPG, PNG, GIF!`,
          type: "error",
        });
      }

      // Limit: Max 1 image upload per request
      const limit = pLimit(1);
      const imageUpload = await limit(async () => {
        const result = await cloudinary.uploader.upload(req.file.path);

        // Delete the temporary file after upload
        if (req.file && req.file.path) {
          fs.unlink(req.file.path, (err) => {
            if (err) console.error("Error deleting temporary file:", err);
          });
        }

        return {
          public_id: result.public_id,
          url: result.secure_url,
        };
      });

      // Get the current maximum position and increment by 1 for the new slide
      const lastSlide = await SlideBannerModel.findOne()
        .sort({ position: -1 })
        .limit(1); // Get the slide with the highest position
      const newPosition = lastSlide ? lastSlide.position + 1 : 1; // Default to position 1 if no slides exist

      // Create a new slide with the uploaded image and position
      const newSlide = new SlideBannerModel({
        images: [imageUpload],
        position: newPosition,
      });

      await newSlide.save();

      res.status(201).json({
        success: true,
        message: "Tạo slide thành công!",
        data: newSlide,
        type: "success",
      });
    } catch (error) {
      console.error("Lỗi:", error);
      res.status(500).json({
        success: false,
        error: error.message,
      });
    }
  }
);

// API UPDATE slide
router.put(
  "/:id",
  verifyToken,
  checkAdminOrOwner,
  upload.single("images"),
  async (req, res) => {
    try {
      // Tìm slide theo ID
      const slide = await SlideBannerModel.findById(req.params.id);

      if (!slide) {
        return res.status(404).json({
          success: false,
          message: "Không tìm thấy slide!",
          type: "error",
        });
      }

      // Xử lý ảnh mới nếu có
      let newImage = null;
      if (req.file) {
        // Xóa ảnh cũ khỏi Cloudinary nếu có
        for (const image of slide.images) {
          await cloudinary.uploader.destroy(image.public_id);
        }

        // Tải ảnh mới lên Cloudinary
        const result = await cloudinary.uploader.upload(req.file.path);

        // Xóa file tạm sau khi tải lên Cloudinary
        fs.unlink(req.file.path, (err) => {
          if (err) console.error("Error deleting temporary file:", err);
        });

        newImage = {
          public_id: result.public_id,
          url: result.secure_url,
        };
      }

      // Cập nhật thông tin slide
      slide.images = newImage ? [newImage] : slide.images; // Nếu có ảnh mới thì thay thế, không thì giữ nguyên
      slide.position = req.body.position || slide.position; // Cập nhật vị trí nếu có

      // Lưu slide sau khi cập nhật
      await slide.save();

      res.status(200).json({
        success: true,
        message: "Cập nhật slide thành công!",
        data: slide,
        type: "success",
      });
    } catch (error) {
      console.error("Lỗi:", error);
      res.status(500).json({
        success: false,
        error: error.message,
      });
    }
  }
);

module.exports = router;
